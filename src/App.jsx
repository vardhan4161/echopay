import { useEffect, useMemo, useRef, useState } from 'react'
import './App.css'
import { buildPacket, bytesToBits, bitsToBytes, parsePacket, PACKET_SIZE } from './packet'
import { signData, verifySignature } from './signer'
import { playBits } from './encoder'
import { startDecoder } from './decoder'

const BIT_DURATION_SEC = 0.03
const PREAMBLE_BITS = [1, 0, 1, 0, 1, 0, 1, 0]
const MAX_PACKET_AGE_SEC = 10
const ACCOUNTS_KEY = 'echopay-accounts'
const CURRENT_ACCOUNT_KEY = 'echopay-current'

const loadAccounts = () => {
  const raw = localStorage.getItem(ACCOUNTS_KEY)
  if (!raw) return []
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

const saveAccounts = (accounts) => {
  localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(accounts))
}

const loadCurrentAccountId = () => {
  const raw = localStorage.getItem(CURRENT_ACCOUNT_KEY)
  if (!raw) return null
  const id = Number.parseInt(raw, 10)
  return Number.isFinite(id) ? id : null
}

const saveCurrentAccountId = (userId) => {
  localStorage.setItem(CURRENT_ACCOUNT_KEY, String(userId))
}

const buildPayload = ({ senderId, amountPaise, timestampSec, nonce }) => {
  const payload = new Uint8Array(14)
  const view = new DataView(payload.buffer)
  view.setUint32(0, senderId)
  view.setUint32(4, amountPaise)
  view.setUint32(8, timestampSec)
  view.setUint16(12, nonce)
  return payload
}

const validatePacket = async (packet) => {
  console.log('Decoded packet bytes:', Array.from(packet))
  const { senderId, amountPaise, timestampSec, nonce, signature } = parsePacket(packet)
  console.log('Decoded amount (paise):', amountPaise)
  console.log('Decoded timestamp (sec):', timestampSec)
  const payload = packet.slice(0, 14)
  const isValid = await verifySignature(payload, signature)
  console.log('Signature valid:', isValid)
  if (!isValid) {
    throw new Error('Invalid signature')
  }
  const now = Math.floor(Date.now() / 1000)
  console.log('Now (sec):', now)
  if (Math.abs(now - timestampSec) > MAX_PACKET_AGE_SEC) {
    throw new Error('Stale timestamp')
  }
  return { senderId, amountPaise, timestampSec, nonce }
}

function App() {
  const [mode, setMode] = useState('send')
  const [amountInput, setAmountInput] = useState('125.00')
  const [sendStatus, setSendStatus] = useState('')
  const [listening, setListening] = useState(false)
  const [received, setReceived] = useState(null)
  const [error, setError] = useState('')
  const [account, setAccount] = useState(null)
  const [usernameInput, setUsernameInput] = useState('')
  const [emailInput, setEmailInput] = useState('')
  const [passwordInput, setPasswordInput] = useState('')
  const [authMode, setAuthMode] = useState('login')
  const [counterpartyIdInput, setCounterpartyIdInput] = useState('')
  const audioContextRef = useRef(null)
  const decoderRef = useRef(null)
  const bitBufferRef = useRef([])
  const expectedSenderIdRef = useRef(null)
  const balance = account?.balance ?? 0
  const userId = account?.userId ?? 0

  const persistAccount = (updated) => {
    const accounts = loadAccounts()
    const next = accounts.some((item) => item.userId === updated.userId)
      ? accounts.map((item) => (item.userId === updated.userId ? updated : item))
      : [...accounts, updated]
    saveAccounts(next)
    saveCurrentAccountId(updated.userId)
  }

  const updateAccount = (updater) => {
    // Use functional state to avoid stale balance during async receive verification.
    setAccount((prev) => {
      if (!prev) return prev
      const next = updater(prev)
      persistAccount(next)
      return next
    })
  }

  useEffect(() => {
    const accounts = loadAccounts()
    const currentId = loadCurrentAccountId()
    if (currentId) {
      const current = accounts.find((item) => item.userId === currentId)
      if (current) {
        setAccount(current)
        setUsernameInput(current.username)
        setEmailInput(current.email)
      }
    }
    return () => {
      stopListening()
      if (audioContextRef.current) {
        audioContextRef.current.close()
      }
    }
  }, [])

  const handleSend = async () => {
    setError('')
    setSendStatus('')
    const amountValue = Number.parseFloat(amountInput)
    if (!Number.isFinite(amountValue) || amountValue <= 0) {
      setError('Enter a valid amount.')
      return
    }
    const amountPaise = Math.round(amountValue * 100)
    if (!account) {
      setError('Log in to send.')
      return
    }
    if (!counterpartyIdInput.trim()) {
      setError('Enter receiver device ID.')
      return
    }
    if (balance < amountValue) {
      setError('Insufficient balance.')
      return
    }
    try {
      const timestampSec = Math.floor(Date.now() / 1000)
      const nonce = crypto.getRandomValues(new Uint16Array(1))[0]
      const payload = buildPayload({ senderId: userId, amountPaise, timestampSec, nonce })
      const signature = await signData(payload)
      const packet = buildPacket({
        senderId: userId,
        amountPaise,
        timestampSec,
        nonce,
        signature,
      })
      // Add a short preamble and a small gap between bits to improve sync.
      const bits = [...PREAMBLE_BITS, ...bytesToBits(packet)]
      setSendStatus('Sending...')
      await playBits(bits, { bitDuration: BIT_DURATION_SEC, gapDuration: 0.004 }, audioContextRef)
      setSendStatus('Sent via sound.')
      updateAccount((prev) => ({ ...prev, balance: prev.balance - amountValue }))
    } catch (err) {
      setError(err.message || 'Send failed.')
    }
  }

  const stopListening = async () => {
    if (decoderRef.current) {
      await decoderRef.current.stop()
      decoderRef.current = null
    }
    bitBufferRef.current = []
    setListening(false)
  }

  const startListening = async () => {
    if (listening) return
    setError('')
    setReceived(null)
    const expectedId = Number.parseInt(counterpartyIdInput, 10)
    if (!Number.isFinite(expectedId)) {
      setError('Enter sender device ID.')
      return
    }
    // Lock the expected sender ID at listen start to avoid rejecting valid packets.
    expectedSenderIdRef.current = expectedId
    try {
      decoderRef.current = await startDecoder({
        bitDuration: BIT_DURATION_SEC,
        onBit: (bit) => {
          const buffer = bitBufferRef.current
          buffer.push(bit)
          const neededBits = PREAMBLE_BITS.length + PACKET_SIZE * 8
          if (buffer.length < neededBits) return
          for (let i = 0; i <= buffer.length - neededBits; i += 1) {
            const match = PREAMBLE_BITS.every(
              (bitValue, idx) => buffer[i + idx] === bitValue,
            )
            if (!match) continue
            const packetStart = i + PREAMBLE_BITS.length
            const packetBits = buffer.slice(packetStart, packetStart + PACKET_SIZE * 8)
            if (packetBits.length < PACKET_SIZE * 8) return
            const packet = bitsToBytes(packetBits)
            stopListening()
            validatePacket(packet)
              .then((data) => {
                const expectedSenderId = expectedSenderIdRef.current
                console.log('Expected sender ID:', expectedSenderId)
                console.log('Packet sender ID:', data.senderId)
                if (!Number.isFinite(expectedSenderId)) {
                  setError('Enter sender device ID.')
                  return
                }
                if (data.senderId !== expectedSenderId) {
                  setError('Sender device ID mismatch.')
                  return
                }
                setReceived(data)
                setError('')
                updateAccount((prev) => ({
                  ...prev,
                  balance: prev.balance + data.amountPaise / 100,
                }))
              })
              .catch((err) => setError(err.message || 'Invalid packet'))
            return
          }
          if (buffer.length > neededBits * 2) {
            buffer.splice(0, buffer.length - neededBits * 2)
          }
        },
      })
      setListening(true)
    } catch (err) {
      setError('Microphone permission denied.')
    }
  }

  const handleCreateAccount = () => {
    setError('')
    const username = usernameInput.trim()
    const email = emailInput.trim()
    const password = passwordInput.trim()
    if (!username || !email || !password) {
      setError('Enter username, email, and password.')
      return
    }
    const accounts = loadAccounts()
    if (accounts.some((item) => item.email === email)) {
      setError('Email already exists.')
      return
    }
    const newAccount = {
      userId: crypto.getRandomValues(new Uint32Array(1))[0],
      username,
      email,
      password,
      balance: 500,
    }
    // Demo-only account system.
    setAccount(newAccount)
    persistAccount(newAccount)
  }

  const handleLogin = () => {
    setError('')
    const email = emailInput.trim()
    const password = passwordInput.trim()
    if (!email || !password) {
      setError('Enter email and password.')
      return
    }
    const accounts = loadAccounts()
    const match = accounts.find((item) => item.email === email && item.password === password)
    if (!match) {
      setError('Invalid credentials.')
      return
    }
    setAccount(match)
    setUsernameInput(match.username)
    saveCurrentAccountId(match.userId)
  }

  const handleResetAccount = () => {
    localStorage.removeItem(CURRENT_ACCOUNT_KEY)
    setAccount(null)
    setUsernameInput('')
    setEmailInput('')
    setPasswordInput('')
    setReceived(null)
    setError('')
  }

  return (
    <div className="app">
      <header className="hero">
        <div>
          <h1>EchoPay</h1>
          <p>Offline sound-based payments via Web Audio FSK.</p>
        </div>
        {account && <div className="badge">User ID: {userId}</div>}
      </header>

      {!account && (
        <section className="card">
          <h2>{authMode === 'login' ? 'Login' : 'Create Account'}</h2>
          <p className="hint">Demo-only account system.</p>
          {authMode === 'signup' && (
            <label className="field">
              Username
              <input
                type="text"
                value={usernameInput}
                onChange={(event) => setUsernameInput(event.target.value)}
                placeholder="Enter a name"
              />
            </label>
          )}
          <label className="field">
            Email
            <input
              type="email"
              value={emailInput}
              onChange={(event) => setEmailInput(event.target.value)}
              placeholder="you@example.com"
            />
          </label>
          <label className="field">
            Password
            <input
              type="password"
              value={passwordInput}
              onChange={(event) => setPasswordInput(event.target.value)}
              placeholder="Demo password"
            />
          </label>
          {authMode === 'login' ? (
            <button className="primary" onClick={handleLogin}>
              Login
            </button>
          ) : (
            <button className="primary" onClick={handleCreateAccount}>
              Create Account
            </button>
          )}
          <button
            className="ghost"
            onClick={() => setAuthMode(authMode === 'login' ? 'signup' : 'login')}
          >
            {authMode === 'login' ? 'Need an account? Sign up' : 'Have an account? Login'}
          </button>
        </section>
      )}

      {account && (
        <section className="card summary">
          <div>
            <h2>{account.username}</h2>
            <p className="balance">Balance ₹{balance.toFixed(2)}</p>
            <p className="hint">Device ID: {userId}</p>
          </div>
          <button className="ghost" onClick={handleResetAccount}>
            Log Out
          </button>
        </section>
      )}

      <section className="mode-switch">
        <button
          className={mode === 'send' ? 'active' : ''}
          onClick={() => {
            setMode('send')
            stopListening()
          }}
        >
          Send
        </button>
        <button
          className={mode === 'receive' ? 'active' : ''}
          onClick={() => {
            setMode('receive')
          }}
        >
          Receive
        </button>
      </section>

      {mode === 'send' && (
        <section className="card">
          <h2>Send via Sound</h2>
          <label className="field">
            Receiver Device ID
            <input
              type="number"
              value={counterpartyIdInput}
              onChange={(event) => setCounterpartyIdInput(event.target.value)}
              placeholder="Enter receiver ID"
            />
          </label>
          <label className="field">
            Amount (INR)
            <input
              type="number"
              inputMode="decimal"
              min="0.01"
              step="0.01"
              value={amountInput}
              onChange={(event) => setAmountInput(event.target.value)}
            />
          </label>
          <button className="primary" onClick={handleSend}>
            Send via Sound
          </button>
          {sendStatus && <p className="status">{sendStatus}</p>}
        </section>
      )}

      {mode === 'receive' && (
        <section className="card">
          <h2>Receive</h2>
          <p className="hint">Tip: use two devices to see different sender IDs.</p>
          <label className="field">
            Sender Device ID
            <input
              type="number"
              value={counterpartyIdInput}
              onChange={(event) => setCounterpartyIdInput(event.target.value)}
              placeholder="Enter sender ID"
            />
          </label>
          {listening ? (
            <div className="listening">
              <span className="dot" />
              Listening...
            </div>
          ) : (
            <button
              className="primary"
              onClick={startListening}
              disabled={!counterpartyIdInput.trim()}
            >
              Start Listening
            </button>
          )}
          {received && (
            <div className="success">
              <h3>Payment received</h3>
              <p>
                From {received.senderId} • ₹{(received.amountPaise / 100).toFixed(2)}
              </p>
              <p>Nonce {received.nonce}</p>
            </div>
          )}
        </section>
      )}

      {error && <p className="error">{error}</p>}
    </div>
  )
  
}

export default App
