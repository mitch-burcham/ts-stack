import { jest } from '@jest/globals'
import { Peer } from '../Peer.js'
import { SessionManager } from '../SessionManager.js'
import { AuthMessage, RequestedCertificateSet, Transport } from '../types.js'
import { PrivateKey } from '../../primitives/index.js'
import { ListCertificatesResult, ProveCertificateResult } from '../../wallet/Wallet.interfaces.js'
import { CompletedProtoWallet } from '../certificates/__tests/CompletedProtoWallet.js'

// A server that asks for certificates in its initialResponse may refuse any general message
// that arrives before the client's certificateResponse (atlas-relay does: it has no queue).
// The default Peer (used by WebSocket clients such as @bsv/authsocket-client, which send
// through toPeer directly) must therefore not let a general message of that session reach the
// transport before its answer to the embedded request has been sent, whether that answer is
// empty or populated. Every way the answer can end must release the message, and the wait is
// bounded.

const certifier = new PrivateKey(9).toPublicKey().toString()
const certificateType = 'z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY='
const requested: RequestedCertificateSet = {
  certifiers: [certifier],
  types: { [certificateType]: ['firstName'] }
}
const serverKey = new PrivateKey(7)
const serverIdentity = serverKey.toPublicKey().toString()
// Wallet certificate lookups take real time (storage, permission checks). Long enough that an
// unordered general message would overtake the answer.
const WALLET_LATENCY_MS = 50

async function settle(ms: number): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, ms))
}

async function turns(count = 20): Promise<void> {
  for (let i = 0; i < count; i++) await new Promise(resolve => setImmediate(resolve))
}

function withinMs<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not happen within ${ms}ms`)), ms)
  })
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer))
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(r => {
    resolve = r
  })
  return { promise, resolve }
}

class SlowNoCertificateWallet extends CompletedProtoWallet {
  override async listCertificates(): Promise<ListCertificatesResult> {
    await settle(WALLET_LATENCY_MS)
    return { totalCertificates: 0, certificates: [] }
  }
}

class SlowCertificateHolderWallet extends CompletedProtoWallet {
  constructor(private readonly privateKey: PrivateKey) {
    super(privateKey)
  }

  override async listCertificates(): Promise<ListCertificatesResult> {
    await settle(WALLET_LATENCY_MS)
    return {
      totalCertificates: 1,
      certificates: [
        {
          type: certificateType,
          serialNumber: 'c2VyaWFsLW51bWJlci0wMDAwMDAwMDAwMDAwMDAwMDA=',
          subject: this.privateKey.toPublicKey().toString(),
          certifier,
          revocationOutpoint: `${'00'.repeat(32)}.0`,
          fields: { firstName: 'ZW5jcnlwdGVk' },
          signature: '3045022100aa'
        }
      ]
    }
  }

  override async proveCertificate(): Promise<ProveCertificateResult> {
    return { keyringForVerifier: { firstName: 'a2V5' } }
  }
}

class SlowUnavailableWallet extends CompletedProtoWallet {
  override async listCertificates(): Promise<ListCertificatesResult> {
    await settle(WALLET_LATENCY_MS)
    throw new Error('wallet unavailable')
  }
}

class SlowDecliningWallet extends SlowCertificateHolderWallet {
  override async proveCertificate(): Promise<ProveCertificateResult> {
    throw new Error('user declined to disclose certificate fields')
  }
}

/** A wallet whose certificate lookup finishes only when the test says so. */
class GatedWallet extends CompletedProtoWallet {
  readonly lookup = deferred<void>()
  override async listCertificates(): Promise<ListCertificatesResult> {
    await this.lookup.promise
    return { totalCertificates: 0, certificates: [] }
  }
}

/** One ordered message channel per connection, as a WebSocket is. */
class SocketLikeTransport implements Transport {
  other?: SocketLikeTransport
  readonly sent: AuthMessage[] = []
  readonly handlerErrors: unknown[] = []
  private receive?: (message: AuthMessage) => Promise<void>

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

/**
 * The server end of the connection, gated the way atlas-relay gates it: once its
 * initialResponse has asked for certificates, a general message of that session is refused
 * (not queued) until a certificateResponse of that session arrives. The certificate decision
 * itself belongs to the server's policy; this model admits after any answer.
 */
function relayLikeConnection(
  clientWallet: CompletedProtoWallet,
  options: {
    clientSessions?: SessionManager
    clientRequests?: RequestedCertificateSet
    serverWallet?: CompletedProtoWallet
  } = {}
): {
  client: Peer
  clientTransport: SocketLikeTransport
  arrivals: string[]
  refused: AuthMessage[]
  admitted: AuthMessage[]
} {
  const clientTransport = new SocketLikeTransport()
  const socket = new SocketLikeTransport()
  clientTransport.other = socket
  socket.other = clientTransport
  const arrivals: string[] = []
  const refused: AuthMessage[] = []
  const admitted: AuthMessage[] = []
  const awaitingCertificates = new Set<string>()

  const serverTransport: Transport = {
    async send(message: AuthMessage): Promise<void> {
      if (message.messageType === 'initialResponse' && message.requestedCertificates != null) {
        awaitingCertificates.add(message.initialNonce as string)
      }
      await socket.send(message)
    },
    async onData(callback: (message: AuthMessage) => Promise<void>): Promise<void> {
      await socket.onData(async message => {
        arrivals.push(message.messageType)
        const session = message.yourNonce as string
        if (message.messageType === 'general') {
          if (awaitingCertificates.has(session)) {
            refused.push(message)
            return
          }
          admitted.push(message)
          return
        }
        if (message.messageType === 'certificateResponse') awaitingCertificates.delete(session)
        await callback(message)
      })
    }
  }
  const server = new Peer(
    options.serverWallet ?? new CompletedProtoWallet(serverKey),
    serverTransport,
    requested,
    new SessionManager()
  )
  void server
  const client = new Peer(
    clientWallet,
    clientTransport,
    options.clientRequests,
    options.clientSessions
  )
  return { client, clientTransport, arrivals, refused, admitted }
}

const payload = [1, 2, 3]

async function untilArrived(arrivals: string[], type: string): Promise<void> {
  await withinMs(
    (async () => {
      while (!arrivals.includes(type)) await settle(5)
    })(),
    3000,
    `arrival of ${type}`
  )
}

describe('a general message waits for the answer to a certificate request embedded in the initialResponse', () => {
  // A timed-out fake-timer test never reaches its own finally.
  afterEach(() => {
    jest.useRealTimers()
  })

  test('empty answer: the first message after the handshake arrives after it and is admitted', async () => {
    const relay = relayLikeConnection(new SlowNoCertificateWallet(new PrivateKey(8)))

    await relay.client.getAuthenticatedSession(serverIdentity)
    await relay.client.toPeer(payload, serverIdentity)
    await untilArrived(relay.arrivals, 'general')

    expect(relay.refused).toEqual([])
    expect(relay.arrivals).toEqual(['initialRequest', 'certificateResponse', 'general'])
    expect(relay.admitted.map(m => m.payload)).toEqual([payload])
    const answer = relay.clientTransport.sent.find(m => m.messageType === 'certificateResponse')
    expect(answer?.certificates).toEqual([])
  }, 15000)

  test('populated answer: the first message after the handshake arrives after it and is admitted', async () => {
    const relay = relayLikeConnection(new SlowCertificateHolderWallet(new PrivateKey(8)))

    await relay.client.getAuthenticatedSession(serverIdentity)
    await relay.client.toPeer(payload, serverIdentity)
    await untilArrived(relay.arrivals, 'general')

    expect(relay.refused).toEqual([])
    expect(relay.arrivals).toEqual(['initialRequest', 'certificateResponse', 'general'])
    const answer = relay.clientTransport.sent.find(m => m.messageType === 'certificateResponse')
    expect(answer?.certificates).toHaveLength(1)
  }, 15000)

  test.each([
    ['a wallet failure', () => new SlowUnavailableWallet(new PrivateKey(8)), 'wallet unavailable'],
    [
      'a declined disclosure',
      () => new SlowDecliningWallet(new PrivateKey(8)),
      'user declined to disclose certificate fields'
    ]
  ])(
    '%s sends no answer and releases the message for the server to decide',
    async (_case, wallet, reason) => {
      const relay = relayLikeConnection(wallet())

      await relay.client.getAuthenticatedSession(serverIdentity)
      await withinMs(relay.client.toPeer(payload, serverIdentity), 1000, 'the general send')
      await untilArrived(relay.arrivals, 'general')

      // Nothing reports the refusal as "no certificates"; the server decides, as it would today.
      expect(relay.clientTransport.sent.map(m => m.messageType)).toEqual([
        'initialRequest',
        'general'
      ])
      expect(relay.refused).toHaveLength(1)
      await withinMs(
        (async () => {
          while (relay.clientTransport.handlerErrors.length === 0) await settle(5)
        })(),
        3000,
        'the wallet error'
      )
      expect(String(relay.clientTransport.handlerErrors[0])).toContain(reason)
    },
    15000
  )

  test('a caller can cancel a message while it waits, and it is never sent', async () => {
    const wallet = new GatedWallet(new PrivateKey(8))
    const relay = relayLikeConnection(wallet)
    const controller = new AbortController()
    const reason = new Error('caller gave up')

    await relay.client.getAuthenticatedSession(serverIdentity)
    const sending = relay.client.toPeer(payload, serverIdentity, controller.signal)
    void sending.catch(() => {})
    await turns()
    expect(relay.clientTransport.sent.map(m => m.messageType)).toEqual(['initialRequest'])

    controller.abort(reason)
    await expect(sending).rejects.toBe(reason)
    wallet.lookup.resolve()
    await untilArrived(relay.arrivals, 'certificateResponse')
    await settle(50)
    expect(relay.clientTransport.sent.map(m => m.messageType)).toEqual([
      'initialRequest',
      'certificateResponse'
    ])
  }, 15000)

  test('a cancelled handshake answer sends nothing and releases the waiting message', async () => {
    const wallet = new GatedWallet(new PrivateKey(8))
    const relay = relayLikeConnection(wallet)
    const handshake = new AbortController()

    await relay.client.getAuthenticatedSession(serverIdentity, handshake.signal)
    const sending = relay.client.toPeer(payload, serverIdentity)
    await turns()
    expect(relay.clientTransport.sent.map(m => m.messageType)).toEqual(['initialRequest'])

    handshake.abort(new Error('handshake owner gave up'))
    wallet.lookup.resolve()
    await withinMs(sending, 1000, 'the general send')
    await untilArrived(relay.arrivals, 'general')

    expect(relay.clientTransport.sent.map(m => m.messageType)).toEqual([
      'initialRequest',
      'general'
    ])
    expect(relay.refused).toHaveLength(1)
  }, 15000)

  test('a wallet that never answers holds the message for at most 30 seconds', async () => {
    jest.useFakeTimers({ doNotFake: ['setImmediate', 'nextTick', 'queueMicrotask'] })
    try {
      const wallet = new GatedWallet(new PrivateKey(8))
      const relay = relayLikeConnection(wallet)

      await relay.client.getAuthenticatedSession(serverIdentity)
      const sending = relay.client.toPeer(payload, serverIdentity)
      await turns()
      await jest.advanceTimersByTimeAsync(29_999)
      await turns()
      expect(relay.clientTransport.sent.map(m => m.messageType)).toEqual(['initialRequest'])

      await jest.advanceTimersByTimeAsync(1)
      await sending
      await turns()
      expect(relay.clientTransport.sent.map(m => m.messageType)).toEqual([
        'initialRequest',
        'general'
      ])
    } finally {
      jest.useRealTimers()
    }
  }, 15000)

  test('an application certificate-request listener owns its own ordering and is never waited on', async () => {
    const relay = relayLikeConnection(new SlowNoCertificateWallet(new PrivateKey(8)))
    const listenerDone = deferred<void>()
    let sentFromListener: Promise<void> | undefined
    relay.client.listenForCertificatesRequested(async verifier => {
      // A listener that itself sends on the session must not deadlock against the hold.
      sentFromListener = relay.client.toPeer(payload, verifier)
      await sentFromListener
      listenerDone.resolve()
    })

    await relay.client.getAuthenticatedSession(serverIdentity)
    await withinMs(listenerDone.promise, 1000, 'the listener')
    await withinMs(sentFromListener as Promise<void>, 1000, 'the listener send')
  }, 15000)

  /**
   * Fires `senders` further toPeer calls from inside the client's own session write, at the
   * instant the session becomes observable as authenticated and before the handshake resolves:
   * the earliest moment any second caller (another emit, a queued send, a poll) can find it.
   */
  function sendersAtAuthentication(
    sessions: SessionManager,
    client: Peer,
    senders: number,
    write: 'updateSessionIfUnauthenticated' | 'updateSession'
  ): { sends: Array<Promise<void>> } {
    const sends: Array<Promise<void>> = []
    const store = sessions as any
    const original = store[write].bind(store)
    store[write] = (session: any) => {
      const result = original(session)
      if (sends.length === 0 && session.isAuthenticated === true) {
        for (let i = 0; i < senders; i++) {
          const send = client.toPeer([9, i], serverIdentity)
          send.catch(() => {})
          sends.push(send)
        }
      }
      return result
    }
    return { sends }
  }

  test.each([
    ['a coordinated session store', 'updateSessionIfUnauthenticated' as const],
    ['a plain session store', 'updateSession' as const]
  ])(
    'a second sender that finds the session authenticated before the handshake resolves is held too (%s)',
    async (_store, write) => {
      const clientSessions = new SessionManager()
      if (write === 'updateSession') {
        // Without the paired coordinated methods the Peer commits through updateSession.
        ;(clientSessions as any).updateSessionIfUnauthenticated = undefined
      }
      const relay = relayLikeConnection(new SlowNoCertificateWallet(new PrivateKey(8)), {
        clientSessions
      })
      const second = sendersAtAuthentication(clientSessions, relay.client, 1, write)

      await relay.client.getAuthenticatedSession(serverIdentity)
      expect(second.sends).toHaveLength(1)
      await withinMs(Promise.all(second.sends), 3000, 'the second send')
      await untilArrived(relay.arrivals, 'general')

      expect(relay.refused).toEqual([])
      expect(relay.arrivals).toEqual(['initialRequest', 'certificateResponse', 'general'])
      expect(relay.admitted.map(m => m.payload)).toEqual([[9, 0]])
    },
    15000
  )

  test('five concurrent senders and the handshake caller all arrive after the answer and are admitted', async () => {
    const clientSessions = new SessionManager()
    const relay = relayLikeConnection(new SlowNoCertificateWallet(new PrivateKey(8)), {
      clientSessions
    })
    const others = sendersAtAuthentication(
      clientSessions,
      relay.client,
      5,
      'updateSessionIfUnauthenticated'
    )

    await relay.client.getAuthenticatedSession(serverIdentity)
    await relay.client.toPeer(payload, serverIdentity)
    await withinMs(Promise.all(others.sends), 3000, 'the concurrent sends')
    await withinMs(
      (async () => {
        while (relay.admitted.length + relay.refused.length < 6) await settle(5)
      })(),
      3000,
      'six general arrivals'
    )

    expect(relay.refused).toEqual([])
    expect(relay.arrivals).toEqual([
      'initialRequest',
      'certificateResponse',
      ...Array<string>(6).fill('general')
    ])
    expect(relay.admitted).toHaveLength(6)
  }, 15000)

  test('a failure after the hold was taken releases it: invalid server certificates', async () => {
    // The client also asks the server for certificates; the server answers in its
    // initialResponse with one that cannot validate, so validation throws after the session
    // was written as authenticated and the hold was taken. No answer will follow.
    const clientSessions = new SessionManager()
    const relay = relayLikeConnection(new SlowNoCertificateWallet(new PrivateKey(8)), {
      clientSessions,
      clientRequests: requested,
      serverWallet: new SlowCertificateHolderWallet(serverKey)
    })
    const second = sendersAtAuthentication(
      clientSessions,
      relay.client,
      1,
      'updateSessionIfUnauthenticated'
    )
    const handshake = new AbortController()
    const handshaking = relay.client.getAuthenticatedSession(serverIdentity, handshake.signal)
    handshaking.catch(() => {})

    try {
      await withinMs(
        (async () => {
          while (second.sends.length === 0) await settle(5)
        })(),
        3000,
        'the session write'
      )
      // Released on the validation failure, well inside the 30-second bound. The released send
      // then meets the client's own unmet certificate requirement and is refused locally.
      const [outcome] = await withinMs(
        Promise.allSettled(second.sends),
        2000,
        'the held send to settle'
      )
      expect(outcome.status).toBe('rejected')
      expect(String((outcome as PromiseRejectedResult).reason)).toContain(
        'Cannot send general message before certificate validation is complete'
      )
      expect(relay.clientTransport.sent.map(m => m.messageType)).toEqual(['initialRequest'])
      expect(relay.clientTransport.handlerErrors).toHaveLength(1)
    } finally {
      handshake.abort(new Error('test done'))
    }
  }, 15000)
})
