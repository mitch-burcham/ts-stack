import { jest } from '@jest/globals'
import * as Utils from '../../../primitives/utils.js'

jest.mock('../../Peer.js', () => ({
  Peer: jest.fn()
}))
jest.unstable_mockModule('../../Peer.js', () => ({
  Peer: jest.fn()
}))

jest.mock('../../transports/SimplifiedFetchTransport.js', () => ({
  SimplifiedFetchTransport: jest.fn(),
  DEFAULT_SIMPLIFIED_FETCH_MAX_RESPONSE_BYTES: 16 * 1024 * 1024
}))
jest.unstable_mockModule('../../transports/SimplifiedFetchTransport.js', () => ({
  SimplifiedFetchTransport: jest.fn(),
  DEFAULT_SIMPLIFIED_FETCH_MAX_RESPONSE_BYTES: 16 * 1024 * 1024
}))

jest.mock('../../utils/getVerifiableCertificates.js', () => ({
  getVerifiableCertificates: jest.fn()
}))
jest.unstable_mockModule('../../utils/getVerifiableCertificates.js', () => ({
  getVerifiableCertificates: jest.fn()
}))

jest.mock('../../../primitives/Random.js', () => ({
  __esModule: true,
  default: jest.fn(() => Array.from({ length: 32 }).fill(7))
}))
jest.unstable_mockModule('../../../primitives/Random.js', () => ({
  __esModule: true,
  default: jest.fn(() => Array.from({ length: 32 }).fill(7))
}))

type AuthFetchConstructor = typeof import('../AuthFetch.js').AuthFetch
type PeerConstructor = typeof import('../../Peer.js').Peer
type SimplifiedFetchTransportConstructor =
  typeof import('../../transports/SimplifiedFetchTransport.js').SimplifiedFetchTransport
type GetVerifiableCertificates =
  typeof import('../../utils/getVerifiableCertificates.js').getVerifiableCertificates

let AuthFetch!: AuthFetchConstructor
let Peer!: PeerConstructor
let SimplifiedFetchTransport!: SimplifiedFetchTransportConstructor
let PeerMock!: jest.Mock
let SimplifiedFetchTransportMock!: jest.Mock
let getVerifiableCertificatesMock!: jest.MockedFunction<GetVerifiableCertificates>

beforeAll(async () => {
  const [authFetchModule, peerModule, transportModule, certificateModule] = await Promise.all([
    import('../AuthFetch.js'),
    import('../../Peer.js'),
    import('../../transports/SimplifiedFetchTransport.js'),
    import('../../utils/getVerifiableCertificates.js')
  ])
  AuthFetch = authFetchModule.AuthFetch
  Peer = peerModule.Peer
  SimplifiedFetchTransport = transportModule.SimplifiedFetchTransport
  PeerMock = Peer as unknown as jest.Mock
  SimplifiedFetchTransportMock = SimplifiedFetchTransport as unknown as jest.Mock
  getVerifiableCertificatesMock =
    certificateModule.getVerifiableCertificates as jest.MockedFunction<GetVerifiableCertificates>
})

function deferred<T>(): {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason: unknown) => void
} {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function buildResponsePayload(
  requestNonce: number[],
  status: number,
  headers: Record<string, string>,
  body: number[]
): number[] {
  const writer = new Utils.Writer()
  writer.write(requestNonce)
  writer.writeVarIntNum(status)
  writer.writeVarIntNum(Object.keys(headers).length)

  for (const [key, value] of Object.entries(headers)) {
    const keyBytes = Utils.toArray(key, 'utf8')
    const valueBytes = Utils.toArray(value, 'utf8')
    writer.writeVarIntNum(keyBytes.length)
    writer.write(keyBytes)
    writer.writeVarIntNum(valueBytes.length)
    writer.write(valueBytes)
  }

  writer.writeVarIntNum(body.length)
  writer.write(body)
  return writer.toArray()
}

afterEach(() => {
  jest.useRealTimers()
  jest.restoreAllMocks()
  PeerMock.mockReset()
  SimplifiedFetchTransportMock.mockReset()
  getVerifiableCertificatesMock.mockReset()
})

describe('AuthFetch authenticated peer lifecycle', () => {
  test('binds the configured originator when a certificate request creates a peer', async () => {
    let certificatesReceived:
      ((senderPublicKey: string, certificates: unknown[]) => void) | undefined
    const peer = {
      ready: Promise.resolve(),
      listenForCertificatesReceived: jest.fn(
        (listener: (senderPublicKey: string, certificates: unknown[]) => void) => {
          certificatesReceived = listener
          return 7
        }
      ),
      listenForCertificatesRequested: jest.fn(),
      stopListeningForCertificatesReceived: jest.fn(),
      requestCertificates: jest.fn(async () => {
        certificatesReceived?.('server-key', [])
      })
    }
    PeerMock.mockImplementation(() => peer)
    const wallet = { getPublicKey: jest.fn() }
    const authFetch = new AuthFetch(wallet as any, undefined, undefined, 'app.example' as any)

    await authFetch.sendCertificateRequest('https://service.example/certificates', {
      certifiers: [],
      types: {}
    })

    expect(PeerMock).toHaveBeenCalledWith(
      wallet,
      expect.anything(),
      undefined,
      expect.anything(),
      undefined,
      'app.example'
    )
  })

  test('creates a peer, exchanges certificates, and resolves an authenticated response', async () => {
    let certificatesReceived:
      ((senderPublicKey: string, certificates: Array<{ serialNumber: string }>) => void) | undefined
    let certificatesRequested:
      | ((verifier: string, requestedCertificates: Record<string, unknown>) => Promise<void>)
      | undefined
    let generalMessage: ((senderPublicKey: string, payload: number[]) => void) | undefined

    const stopListeningForGeneralMessages = jest.fn()
    const sendCertificateResponse = jest.fn(async () => {})
    const responseBody = Utils.toArray('authenticated response', 'utf8')
    const peer = {
      ready: Promise.resolve(),
      listenForCertificatesReceived: jest.fn((listener: typeof certificatesReceived) => {
        certificatesReceived = listener
      }),
      listenForCertificatesRequested: jest.fn((listener: typeof certificatesRequested) => {
        certificatesRequested = listener
      }),
      listenForGeneralMessages: jest.fn((listener: typeof generalMessage) => {
        generalMessage = listener
        return 19
      }),
      stopListeningForGeneralMessages,
      sendCertificateResponse,
      toPeer: jest.fn(async () => {
        generalMessage?.(
          'unrelated-server',
          buildResponsePayload(Array.from({ length: 32 }).fill(8), 500, {}, [])
        )
        generalMessage?.(
          'server-identity-key',
          buildResponsePayload(
            Array.from({ length: 32 }).fill(7),
            201,
            { 'content-type': 'text/plain', 'x-test': 'passed' },
            responseBody
          )
        )
      })
    }

    PeerMock.mockImplementation(() => peer)
    const requestedCertificates = {
      certifiers: ['certifier'],
      types: { identity: ['name'] }
    }
    const wallet = { getPublicKey: jest.fn() }
    const authFetch = new AuthFetch(
      wallet as any,
      requestedCertificates as any,
      undefined,
      'app.example' as any
    )
    jest.spyOn(authFetch as any, 'wait').mockResolvedValue(undefined)

    const response = await authFetch.fetch('https://service.example/resource?mode=full', {
      method: 'POST',
      headers: { 'x-bsv-request': 'test' },
      body: [1, 2, 3]
    })

    expect(SimplifiedFetchTransportMock).toHaveBeenCalledWith(
      'https://service.example',
      undefined,
      {}
    )
    expect(PeerMock).toHaveBeenCalledWith(
      wallet,
      expect.anything(),
      requestedCertificates,
      expect.anything(),
      undefined,
      'app.example'
    )
    expect(response.status).toBe(201)
    expect(response.headers.get('x-test')).toBe('passed')
    expect(response.headers.get('x-bsv-auth-identity-key')).toBe('server-identity-key')
    await expect(response.text()).resolves.toBe('authenticated response')
    expect(stopListeningForGeneralMessages).toHaveBeenCalledWith(19)
    expect(authFetch.peers['https://service.example']).toMatchObject({
      identityKey: 'server-identity-key',
      supportsMutualAuth: true
    })

    peer.toPeer.mockImplementationOnce(async () => {
      generalMessage?.(
        'server-identity-key',
        buildResponsePayload(Array.from({ length: 32 }).fill(7), 204, {}, [])
      )
    })
    const emptyResponse = await authFetch.fetch('https://service.example/empty')
    expect(emptyResponse.status).toBe(204)
    await expect(emptyResponse.text()).resolves.toBe('')

    certificatesReceived?.('server-identity-key', [{ serialNumber: 'received-certificate' }])
    expect(authFetch.consumeReceivedCertificates()).toEqual([
      { serialNumber: 'received-certificate' }
    ])

    const certificateToSend = { serialNumber: 'certificate-to-send' }
    getVerifiableCertificatesMock.mockResolvedValue([certificateToSend] as any)
    await certificatesRequested?.('server-identity-key', requestedCertificates)
    expect(getVerifiableCertificatesMock).toHaveBeenCalledWith(
      wallet,
      requestedCertificates,
      'server-identity-key',
      'app.example'
    )
    expect(sendCertificateResponse).toHaveBeenCalledWith('server-identity-key', [certificateToSend])

    getVerifiableCertificatesMock.mockResolvedValue([])
    await certificatesRequested?.('server-identity-key', requestedCertificates)
    expect(sendCertificateResponse).toHaveBeenCalledTimes(1)
    expect(authFetch.peers['https://service.example'].pendingCertificateRequests).toEqual([])
  })

  test('waits for pending certificate decisions before sending', async () => {
    const authFetch = new AuthFetch({} as any)
    const peer = {
      listenForGeneralMessages: jest.fn(() => 1),
      toPeer: jest.fn(async () => {
        throw new Error('stop after certificate wait')
      }),
      pendingCertificateRequests: [true]
    }
    ;(authFetch as any).peers['https://service.example'] = {
      peer,
      pendingCertificateRequests: peer.pendingCertificateRequests
    }
    const waitForPending = jest
      .spyOn(authFetch as any, 'waitForPendingCertificateRequests')
      .mockResolvedValue(undefined)

    await expect(authFetch.fetch('https://service.example/resource')).rejects.toThrow(
      'stop after certificate wait'
    )
    expect(waitForPending).toHaveBeenCalledWith(
      (authFetch as any).peers['https://service.example'],
      expect.any(AbortSignal)
    )
    expect(peer.toPeer).toHaveBeenCalledTimes(1)
  })

  test('does not send after late certificate approval and the 500 ms queue-release delay', async () => {
    jest.useFakeTimers()
    let certificatesRequested:
      | ((verifier: string, requestedCertificates: Record<string, unknown>) => Promise<void>)
      | undefined
    const peer = {
      ready: Promise.resolve(),
      listenForCertificatesReceived: jest.fn(),
      listenForCertificatesRequested: jest.fn((listener: typeof certificatesRequested) => {
        certificatesRequested = listener
      }),
      listenForGeneralMessages: jest.fn(() => 51),
      stopListeningForGeneralMessages: jest.fn(),
      sendCertificateResponse: jest.fn(),
      toPeer: jest.fn()
    }
    PeerMock.mockImplementation(() => peer)
    const permission = deferred<any[]>()
    getVerifiableCertificatesMock.mockReturnValue(permission.promise as any)
    const authFetch = new AuthFetch({} as any)
    const peerState = await (authFetch as any).getOrCreatePeer('https://service.example')
    const requestedCertificates = { certifiers: ['certifier'], types: { identity: ['name'] } }

    const certificateWork = certificatesRequested?.(
      'server-identity-key',
      requestedCertificates
    ) as Promise<void>
    expect(peerState.pendingCertificateRequests).toEqual([true])

    const rejection = authFetch
      .fetch('https://service.example/resource', { method: 'POST' })
      .catch(error => error)
    await jest.advanceTimersByTimeAsync(100)
    expect(peer.toPeer).not.toHaveBeenCalled()
    expect(jest.getTimerCount()).toBe(2)

    await jest.advanceTimersByTimeAsync(29900)
    await expect(rejection).resolves.toMatchObject({
      message: 'Timed out waiting for authenticated response.'
    })
    expect(peer.toPeer).not.toHaveBeenCalled()
    expect(jest.getTimerCount()).toBe(0)

    permission.resolve([])
    await jest.advanceTimersByTimeAsync(0)
    expect(peerState.pendingCertificateRequests).toEqual([true])
    expect(jest.getTimerCount()).toBe(1)

    await jest.advanceTimersByTimeAsync(499)
    expect(peerState.pendingCertificateRequests).toEqual([true])
    expect(peer.toPeer).not.toHaveBeenCalled()

    await jest.advanceTimersByTimeAsync(1)
    await certificateWork
    expect(peerState.pendingCertificateRequests).toEqual([])
    expect(peer.toPeer).not.toHaveBeenCalled()
    expect(jest.getTimerCount()).toBe(0)
  })

  test('releases the queue after late certificate denial without a resource send or timer leak', async () => {
    jest.useFakeTimers()
    let certificatesRequested:
      | ((verifier: string, requestedCertificates: Record<string, unknown>) => Promise<void>)
      | undefined
    const peer = {
      ready: Promise.resolve(),
      listenForCertificatesReceived: jest.fn(),
      listenForCertificatesRequested: jest.fn((listener: typeof certificatesRequested) => {
        certificatesRequested = listener
      }),
      listenForGeneralMessages: jest.fn(() => 52),
      stopListeningForGeneralMessages: jest.fn(),
      sendCertificateResponse: jest.fn(),
      toPeer: jest.fn()
    }
    PeerMock.mockImplementation(() => peer)
    const permission = deferred<any[]>()
    getVerifiableCertificatesMock.mockReturnValue(permission.promise as any)
    const authFetch = new AuthFetch({} as any)
    const peerState = await (authFetch as any).getOrCreatePeer('https://service.example')
    const requestedCertificates = { certifiers: ['certifier'], types: { identity: ['name'] } }

    const certificateWork = certificatesRequested?.(
      'server-identity-key',
      requestedCertificates
    ) as Promise<void>
    const denial = new Error('certificate permission denied')
    const denied = expect(certificateWork).rejects.toBe(denial)
    const rejection = authFetch
      .fetch('https://service.example/resource', { method: 'POST' })
      .catch(error => error)

    await jest.advanceTimersByTimeAsync(30000)
    await expect(rejection).resolves.toMatchObject({
      message: 'Timed out waiting for authenticated response.'
    })
    expect(peer.toPeer).not.toHaveBeenCalled()
    expect(jest.getTimerCount()).toBe(0)

    permission.reject(denial)
    await jest.advanceTimersByTimeAsync(0)
    expect(peerState.pendingCertificateRequests).toEqual([true])
    expect(jest.getTimerCount()).toBe(1)

    await jest.advanceTimersByTimeAsync(500)
    await denied
    expect(peerState.pendingCertificateRequests).toEqual([])
    expect(peer.toPeer).not.toHaveBeenCalled()
    expect(peer.sendCertificateResponse).not.toHaveBeenCalled()
    expect(jest.getTimerCount()).toBe(0)
  })

  test('retries stale sessions and resolves the recursive response', async () => {
    const authFetch = new AuthFetch({} as any)
    ;(authFetch as any).peers['https://service.example'] = {
      peer: {
        listenForGeneralMessages: jest.fn(() => 1),
        toPeer: jest.fn(async () => {
          throw new Error('Session not found for nonce expired')
        })
      },
      identityKey: 'stale-server-key',
      supportsMutualAuth: true,
      pendingCertificateRequests: []
    }

    const originalFetchWithinDeadline = (authFetch as any).fetchWithinDeadline.bind(authFetch)
    const recoveredResponse = new Response('recovered', { status: 200 })
    const fetchSpy = jest.spyOn(authFetch as any, 'fetchWithinDeadline')
    fetchSpy
      .mockImplementationOnce((url, config, deadline, dispatchState) =>
        originalFetchWithinDeadline(url, config, deadline, dispatchState)
      )
      .mockResolvedValueOnce(recoveredResponse)

    await expect(
      authFetch.fetch('https://service.example/resource', { retryCounter: 2 })
    ).resolves.toBe(recoveredResponse)
    expect(fetchSpy).toHaveBeenCalledTimes(2)
    expect(authFetch.peers['https://service.example']).toBeUndefined()
  })

  test('refreshes authenticated sessions rejected with HTTP 401 details', async () => {
    const authFetch = new AuthFetch({} as any)
    const staleError = Object.assign(
      new Error('request arrived without valid BSV authentication'),
      { details: { status: 401 } }
    )
    ;(authFetch as any).peers['https://service.example'] = {
      peer: {
        listenForGeneralMessages: jest.fn(() => 1),
        toPeer: jest.fn(async () => {
          throw staleError
        })
      },
      identityKey: 'stale-server-key',
      supportsMutualAuth: true,
      pendingCertificateRequests: []
    }

    const originalFetchWithinDeadline = (authFetch as any).fetchWithinDeadline.bind(authFetch)
    const recoveredResponse = new Response('recovered', { status: 200 })
    const fetchSpy = jest.spyOn(authFetch as any, 'fetchWithinDeadline')
    fetchSpy
      .mockImplementationOnce((url, config, deadline, dispatchState) =>
        originalFetchWithinDeadline(url, config, deadline, dispatchState)
      )
      .mockResolvedValueOnce(recoveredResponse)

    await expect(authFetch.fetch('https://service.example/resource')).resolves.toBe(
      recoveredResponse
    )
    expect(fetchSpy.mock.calls[1]?.[1]?.retryCounter).toBe(3)
    expect(authFetch.peers['https://service.example']).toBeUndefined()
  })

  test('falls back to validated HTTP after peer authentication failure', async () => {
    const authFetch = new AuthFetch({} as any)
    ;(authFetch as any).peers['https://service.example'] = {
      peer: {
        listenForGeneralMessages: jest.fn(() => 1),
        toPeer: jest.fn(async () => {
          throw new Error('HTTP server failed to authenticate')
        })
      },
      pendingCertificateRequests: []
    }
    const fallbackResponse = new Response('fallback', { status: 200 })
    const fallback = jest
      .spyOn(authFetch as any, 'handleFetchAndValidate')
      .mockResolvedValue(fallbackResponse)

    await expect(authFetch.fetch('https://service.example/resource')).resolves.toBe(
      fallbackResponse
    )
    expect(fallback).toHaveBeenCalledTimes(1)
  })

  test('propagates both validated HTTP and unrelated peer failures', async () => {
    const authFetch = new AuthFetch({} as any)
    const toPeer = jest.fn()
    ;(authFetch as any).peers['https://service.example'] = {
      peer: {
        listenForGeneralMessages: jest.fn(() => 1),
        toPeer
      },
      pendingCertificateRequests: []
    }
    jest
      .spyOn(authFetch as any, 'handleFetchAndValidate')
      .mockRejectedValue(new Error('validated fallback failed'))

    toPeer.mockRejectedValueOnce(new Error('HTTP server failed to authenticate'))
    await expect(authFetch.fetch('https://service.example/first')).rejects.toThrow(
      'validated fallback failed'
    )

    toPeer.mockRejectedValueOnce(new Error('peer transport failed'))
    await expect(authFetch.fetch('https://service.example/second')).rejects.toThrow(
      'peer transport failed'
    )
  })
})
