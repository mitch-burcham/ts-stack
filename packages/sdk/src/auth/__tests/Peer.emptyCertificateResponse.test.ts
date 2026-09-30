import { AuthFetch } from '../clients/AuthFetch.js'
import { Peer } from '../Peer.js'
import { SessionManager } from '../SessionManager.js'
import { SimplifiedFetchTransport } from '../transports/SimplifiedFetchTransport.js'
import { AuthMessage, RequestedCertificateSet, Transport } from '../types.js'
import { VerifiableCertificate } from '../certificates/VerifiableCertificate.js'
import { PrivateKey } from '../../primitives/index.js'
import { normalizeBRC100ByteFields, stringifyBRC100 } from '../../wallet/BRC100ByteEncoding.js'
import { ListCertificatesResult, ProveCertificateResult } from '../../wallet/Wallet.interfaces.js'
import { CompletedProtoWallet } from '../certificates/__tests/CompletedProtoWallet.js'

// A certificate-less client asked for certificates in the server's initialResponse must say so
// with an empty certificateResponse, on both the Peer default path (used by WebSocket clients)
// and the AuthFetch listener path. Over HTTP the empty answer must never be open at the server
// at the same time as a later message of the same session: the server keys those messages by
// the client's session nonce, and that overlap is the race the February 2026 guard avoided.

const SERVER_URL = 'https://certificate-gated.example'
// Well inside a server's 30 s certificate deadline, so an answer cannot be mistaken for the
// timeout path.
const ANSWER_DEADLINE_MS = 3000
// Longer than AuthFetch's 500 ms post-answer grace, so the ordering under test cannot rest on it.
const SLOW_SERVER_MS = 750

const certifier = new PrivateKey(9).toPublicKey().toString()
const certificateType = 'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY='
const requested: RequestedCertificateSet = {
  certifiers: [certifier],
  types: { [certificateType]: ['firstName'] }
}

class NoCertificateWallet extends CompletedProtoWallet {
  override async listCertificates(): Promise<ListCertificatesResult> {
    return { totalCertificates: 0, certificates: [] }
  }
}

function heldCertificate(subject: string): ListCertificatesResult['certificates'][number] {
  return {
    type: certificateType,
    serialNumber: 'c2VyaWFsLW51bWJlci0wMDAwMDAwMDAwMDAwMDAwMDA=',
    subject,
    certifier,
    revocationOutpoint: `${'00'.repeat(32)}.0`,
    fields: { firstName: 'ZW5jcnlwdGVk' },
    signature: '3045022100aa'
  }
}

class CertificateHolderWallet extends CompletedProtoWallet {
  constructor(private readonly privateKey: PrivateKey) {
    super(privateKey)
  }

  override async listCertificates(): Promise<ListCertificatesResult> {
    return {
      totalCertificates: 1,
      certificates: [heldCertificate(this.privateKey.toPublicKey().toString())]
    }
  }

  override async proveCertificate(): Promise<ProveCertificateResult> {
    return { keyringForVerifier: { firstName: 'a2V5' } }
  }
}

class UnavailableWallet extends CompletedProtoWallet {
  override async listCertificates(): Promise<ListCertificatesResult> {
    throw new Error('wallet unavailable')
  }
}

/** Holds a matching certificate, but its user refuses to disclose it. */
class DecliningWallet extends CertificateHolderWallet {
  override async proveCertificate(): Promise<ProveCertificateResult> {
    throw new Error('user declined to disclose certificate fields')
  }
}

async function identityOf(wallet: CompletedProtoWallet): Promise<string> {
  return (await wallet.getPublicKey({ identityKey: true })).publicKey
}

function withinMs<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not arrive within ${ms}ms`)), ms)
  })
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer))
}

async function settle(ms: number): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, ms))
}

/** An ordered message channel between two Peers, as a WebSocket connection is. */
class SocketLikeTransport implements Transport {
  other?: SocketLikeTransport
  readonly sent: AuthMessage[] = []
  readonly handlerErrors: unknown[] = []
  private receive?: (message: AuthMessage) => Promise<void>

  static pair(): [SocketLikeTransport, SocketLikeTransport] {
    const a = new SocketLikeTransport()
    const b = new SocketLikeTransport()
    a.other = b
    b.other = a
    return [a, b]
  }

  async send(message: AuthMessage): Promise<void> {
    this.sent.push(message)
    const other = this.other as SocketLikeTransport
    setImmediate(() => {
      void other.receive?.(message).catch(error => other.handlerErrors.push(error))
    })
  }

  async onData(callback: (message: AuthMessage) => Promise<void>): Promise<void> {
    this.receive = callback
  }
}

interface CertificateDecision {
  sender: string
  peerNonce: string
  certificates: VerifiableCertificate[]
}

function json(status: number, body: unknown): Response {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' }
  })
}

/**
 * A certificate-requesting HTTP server built the way `auth-express-middleware` routes
 * `/.well-known/auth`: every non-general message opens a response handle keyed by
 * `x-bsv-auth-request-id ?? initialNonce` (the client's session nonce), a second message
 * arriving while that handle is open is refused as a duplicate (and recorded here as a
 * collision), the server Peer's reply goes to the handle named by its `yourNonce`, and the
 * certificate decision for a handshake is made once, on the first certificate event,
 * answering an empty list with 400 ERR_CERTIFICATES_REQUIRED. `certificateResponseDelayMs`
 * models a server that takes that long to process a certificateResponse.
 */
function handleKeyedServer(options: { certificateResponseDelayMs?: number } = {}): {
  fetchClient: typeof fetch
  serverIdentity: string
  sessions: SessionManager
  received: AuthMessage[]
  collisions: Array<{ requestId: string; messageType: string }>
  statuses: Array<{ messageType: string; status: number }>
  pendingDecisions: Set<string>
  decision: Promise<CertificateDecision>
} {
  const serverKey = new PrivateKey(7)
  const sessions = new SessionManager()
  const openHandles = new Map<string, (response: Response) => void>()
  const received: AuthMessage[] = []
  const collisions: Array<{ requestId: string; messageType: string }> = []
  const statuses: Array<{ messageType: string; status: number }> = []
  const pendingDecisions = new Set<string>()
  let resolveDecision!: (decision: CertificateDecision) => void
  const decision = new Promise<CertificateDecision>(resolve => {
    resolveDecision = resolve
  })
  let receive: ((message: AuthMessage) => Promise<void>) | undefined

  const respond = (requestId: string, response: Response): boolean => {
    const handle = openHandles.get(requestId)
    if (handle === undefined) return false
    openHandles.delete(requestId)
    handle(response)
    return true
  }

  const transport: Transport = {
    async send(message: AuthMessage): Promise<void> {
      if (!respond(message.yourNonce as string, json(200, stringifyBRC100(message)))) {
        throw new Error('No open handles to this peer!')
      }
    },
    async onData(callback: (message: AuthMessage) => Promise<void>): Promise<void> {
      receive = callback
    }
  }
  const peer = new Peer(new NoCertificateWallet(serverKey), transport, requested, sessions)
  peer.listenForCertificatesReceived((sender, certificates, _sessionNonce, peerNonce) => {
    if (peerNonce === undefined || !pendingDecisions.delete(peerNonce)) return
    resolveDecision({ sender, peerNonce, certificates })
    respond(
      peerNonce,
      certificates.length === 0
        ? json(400, { status: 'error', code: 'ERR_CERTIFICATES_REQUIRED' })
        : json(200, { status: 'certificates received' })
    )
  })

  const fetchClient = (async (input: string | URL | Request, init?: RequestInit) => {
    if (!String(input).endsWith('/.well-known/auth')) {
      return new Response('general requests are not served by this fixture', { status: 503 })
    }
    await peer.ready
    const message = normalizeBRC100ByteFields(JSON.parse(String(init?.body)), [
      'payload',
      'signature'
    ]) as AuthMessage
    received.push(message)
    const requestId =
      new Headers(init?.headers).get('x-bsv-auth-request-id') ?? (message.initialNonce as string)
    let response: Response
    if (openHandles.has(requestId)) {
      collisions.push({ requestId, messageType: message.messageType })
      response = json(400, { status: 'error', code: 'ERR_DUPLICATE_REQUEST_ID' })
    } else {
      const reply = new Promise<Response>(resolve => openHandles.set(requestId, resolve))
      const timeout = setTimeout(
        () => respond(requestId, json(408, { code: 'ERR_AUTH_TIMEOUT' })),
        5000
      )
      timeout.unref?.()
      if (message.messageType === 'initialRequest') pendingDecisions.add(requestId)
      const delay =
        message.messageType === 'certificateResponse'
          ? (options.certificateResponseDelayMs ?? 0)
          : 0
      void (async () => {
        if (delay > 0) await settle(delay)
        await (receive as (message: AuthMessage) => Promise<void>)(message)
      })().catch(() => respond(requestId, json(500, { code: 'ERR_INTERNAL_SERVER_ERROR' })))
      response = await reply
      clearTimeout(timeout)
    }
    statuses.push({ messageType: message.messageType, status: response.status })
    return response
  }) as typeof fetch

  return {
    fetchClient,
    serverIdentity: serverKey.toPublicKey().toString(),
    sessions,
    received,
    collisions,
    statuses,
    pendingDecisions,
    decision
  }
}

describe('Peer default path: a certificate request embedded in the initialResponse', () => {
  function socketPair(clientWallet: CompletedProtoWallet): {
    client: Peer
    server: Peer
    clientTransport: SocketLikeTransport
    serverSessions: SessionManager
    serverDecisions: Promise<CertificateDecision>
  } {
    const [clientTransport, serverTransport] = SocketLikeTransport.pair()
    const serverSessions = new SessionManager()
    const client = new Peer(clientWallet, clientTransport)
    const server = new Peer(
      new NoCertificateWallet(new PrivateKey(7)),
      serverTransport,
      requested,
      serverSessions
    )
    const serverDecisions = new Promise<CertificateDecision>(resolve => {
      server.listenForCertificatesReceived((sender, certificates, _sessionNonce, peerNonce) => {
        resolve({ sender, peerNonce: peerNonce as string, certificates })
      })
    })
    return { client, server, clientTransport, serverSessions, serverDecisions }
  }

  test('a client holding no requested certificate answers with an empty certificateResponse the requester can decide on', async () => {
    const clientWallet = new NoCertificateWallet(new PrivateKey(8))
    const clientIdentity = await identityOf(clientWallet)
    const { client, clientTransport, serverSessions, serverDecisions } = socketPair(clientWallet)

    const session = await client.getAuthenticatedSession(new PrivateKey(7).toPublicKey().toString())

    const decision = await withinMs(serverDecisions, ANSWER_DEADLINE_MS, 'certificateResponse')
    expect(decision.sender).toBe(clientIdentity)
    expect(decision.certificates).toEqual([])
    // Bound to the handshake that asked, not to some other session of this identity.
    expect(decision.peerNonce).toBe(session.sessionNonce)
    expect(clientTransport.sent.map(m => m.messageType)).toEqual([
      'initialRequest',
      'certificateResponse'
    ])
    expect(clientTransport.sent[1].certificates).toEqual([])

    // The empty answer validated nothing: the requester's session still owes certificates.
    const serverSession = serverSessions.getSession(clientIdentity)
    expect(serverSession?.isAuthenticated).toBe(true)
    expect(serverSession?.certificatesRequired).toBe(true)
    expect(serverSession?.certificatesValidated).toBe(false)
  }, 15000)

  test('a client holding a requested certificate still sends exactly that certificate', async () => {
    const clientKey = new PrivateKey(8)
    const { client, clientTransport } = socketPair(new CertificateHolderWallet(clientKey))

    await client.getAuthenticatedSession(new PrivateKey(7).toPublicKey().toString())
    await settle(100)

    const responses = clientTransport.sent.filter(m => m.messageType === 'certificateResponse')
    expect(responses).toHaveLength(1)
    expect(responses[0].certificates).toHaveLength(1)
    expect(responses[0].certificates?.[0]).toMatchObject({
      type: certificateType,
      certifier,
      keyring: { firstName: 'a2V5' }
    })
  }, 15000)

  test.each([
    ['a wallet failure', () => new UnavailableWallet(new PrivateKey(8)), 'wallet unavailable'],
    [
      'a declined disclosure',
      () => new DecliningWallet(new PrivateKey(8)),
      'user declined to disclose certificate fields'
    ]
  ])(
    '%s sends nothing and surfaces the error',
    async (_case, wallet, reason) => {
      const { client, clientTransport } = socketPair(wallet())

      await client.getAuthenticatedSession(new PrivateKey(7).toPublicKey().toString())
      await settle(200)

      // A refusal must never be reported as "I hold no certificate".
      expect(clientTransport.sent.map(m => m.messageType)).toEqual(['initialRequest'])
      const surfaced = await withinMs(
        (async () => {
          while (clientTransport.handlerErrors.length === 0) await settle(10)
          return clientTransport.handlerErrors[0]
        })(),
        ANSWER_DEADLINE_MS,
        'the wallet error'
      )
      expect((surfaced as Error).message).toContain(reason)
    },
    15000
  )
})

describe('the empty answer over HTTP never overlaps a later message of the same session', () => {
  test('Peer default path: a certificateRequest issued right after the handshake waits for the empty answer to be decided', async () => {
    const server = handleKeyedServer({ certificateResponseDelayMs: SLOW_SERVER_MS })
    const clientWallet = new NoCertificateWallet(new PrivateKey(8))
    const client = new Peer(
      clientWallet,
      new SimplifiedFetchTransport(SERVER_URL, server.fetchClient)
    )
    const serverAnswer = new Promise<VerifiableCertificate[]>(resolve => {
      client.listenForCertificatesReceived((_sender, certificates) => resolve(certificates))
    })

    // Performs the handshake, answers the embedded request, then sends its own request.
    await client.requestCertificates(requested, server.serverIdentity)

    const outcome = await withinMs(
      serverAnswer,
      SLOW_SERVER_MS + ANSWER_DEADLINE_MS,
      "the server's certificateResponse"
    ).catch((error: unknown) => error)

    // No message of this session was ever open at the server alongside another.
    expect(server.collisions).toEqual([])
    expect(outcome).toEqual([])
    expect(server.received.map(m => m.messageType)).toEqual([
      'initialRequest',
      'certificateResponse',
      'certificateRequest'
    ])
    const decision = await withinMs(server.decision, ANSWER_DEADLINE_MS, 'the certificate decision')
    expect(decision.certificates).toEqual([])
    expect(server.pendingDecisions.size).toBe(0)
    expect(server.statuses).toEqual([
      { messageType: 'initialRequest', status: 200 },
      { messageType: 'certificateResponse', status: 400 },
      { messageType: 'certificateRequest', status: 200 }
    ])
  }, 15000)

  test('AuthFetch: sendCertificateRequest on a new peer waits for the empty answer even when the server outlasts the 500 ms grace', async () => {
    const server = handleKeyedServer({ certificateResponseDelayMs: SLOW_SERVER_MS })
    const authFetch = new AuthFetch(
      new NoCertificateWallet(new PrivateKey(8)),
      undefined,
      undefined,
      undefined,
      {},
      server.fetchClient
    )

    const outcome = await withinMs(
      authFetch.sendCertificateRequest(SERVER_URL, requested),
      SLOW_SERVER_MS + ANSWER_DEADLINE_MS,
      "the server's certificateResponse"
    ).catch((error: unknown) => error)

    expect(server.collisions).toEqual([])
    expect(outcome).toEqual([])
    expect(server.received.map(m => m.messageType)).toEqual([
      'initialRequest',
      'certificateResponse',
      'certificateRequest'
    ])
    const decision = await withinMs(server.decision, ANSWER_DEADLINE_MS, 'the certificate decision')
    expect(decision.certificates).toEqual([])
    expect(server.statuses.map(s => s.status)).toEqual([200, 400, 200])
  }, 15000)
})

describe('AuthFetch answers a handshake certificate request', () => {
  test('a client holding no requested certificate sends an empty certificateResponse promptly', async () => {
    const server = handleKeyedServer()
    const clientWallet = new NoCertificateWallet(new PrivateKey(8))
    const clientIdentity = await identityOf(clientWallet)
    const authFetch = new AuthFetch(
      clientWallet,
      undefined,
      undefined,
      undefined,
      {},
      server.fetchClient
    )

    const request = authFetch.fetch(`${SERVER_URL}/resource`).catch(() => undefined)

    const decision = await withinMs(server.decision, ANSWER_DEADLINE_MS, 'certificateResponse')
    expect(decision.sender).toBe(clientIdentity)
    expect(decision.certificates).toEqual([])
    expect(server.pendingDecisions.size).toBe(0)
    const answer = server.received.find(m => m.messageType === 'certificateResponse')
    expect(answer?.identityKey).toBe(clientIdentity)
    expect(answer?.certificates).toEqual([])

    const session = server.sessions.getSession(clientIdentity)
    expect(session?.isAuthenticated).toBe(true)
    expect(session?.certificatesRequired).toBe(true)
    expect(session?.certificatesValidated).toBe(false)

    await request
  }, 15000)

  test('a client holding a requested certificate still sends exactly that certificate', async () => {
    const server = handleKeyedServer()
    const authFetch = new AuthFetch(
      new CertificateHolderWallet(new PrivateKey(8)),
      undefined,
      undefined,
      undefined,
      {},
      server.fetchClient
    )

    const request = authFetch.fetch(`${SERVER_URL}/resource`).catch(() => undefined)

    // This fixture certificate cannot pass the server's validation, so observe the wire.
    await withinMs(
      (async () => {
        while (!server.received.some(m => m.messageType === 'certificateResponse')) await settle(10)
      })(),
      ANSWER_DEADLINE_MS,
      'certificateResponse'
    )
    const answers = server.received.filter(m => m.messageType === 'certificateResponse')
    expect(answers).toHaveLength(1)
    expect(answers[0].certificates?.[0]).toMatchObject({
      type: certificateType,
      certifier,
      keyring: { firstName: 'a2V5' }
    })

    await request
  }, 15000)

  test.each([
    ['a wallet failure', () => new UnavailableWallet(new PrivateKey(8)), 'wallet unavailable'],
    [
      'a declined disclosure',
      () => new DecliningWallet(new PrivateKey(8)),
      'user declined to disclose certificate fields'
    ]
  ])(
    '%s sends nothing and rejects the request with it',
    async (_case, wallet, reason) => {
      const server = handleKeyedServer()
      const authFetch = new AuthFetch(
        wallet(),
        undefined,
        undefined,
        undefined,
        {},
        server.fetchClient
      )

      await expect(
        withinMs(authFetch.fetch(`${SERVER_URL}/resource`), ANSWER_DEADLINE_MS, 'the rejection')
      ).rejects.toThrow(reason)
      await settle(100)

      expect(server.received.map(m => m.messageType)).toEqual(['initialRequest'])
      expect(server.pendingDecisions.size).toBe(1)
    },
    15000
  )
})
