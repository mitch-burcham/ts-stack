import { jest } from '@jest/globals'

import { Peer } from '../../Peer.js'
import { AsyncSessionManager, SessionManager } from '../../SessionManager.js'
import { AuthMessage, PeerSession, Transport } from '../../types.js'
import { SimplifiedFetchTransport } from '../../transports/SimplifiedFetchTransport.js'
import { PrivateKey } from '../../../primitives/index.js'
import { WalletInterface } from '../../../wallet/Wallet.interfaces.js'
import { AuthFetch } from '../AuthFetch.js'

const baseUrl = 'https://deadline.example'
const serverIdentityKey = new PrivateKey(41).toPublicKey().toString()
const clientIdentityKey = new PrivateKey(42).toPublicKey().toString()
const sessionNonce = 'AQIDBAUGBwgJCgsMDQ4PEA=='

interface Deferred<T> {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason: unknown) => void
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function makeWallet(
  createSignature: jest.Mock = jest.fn(async () => ({ signature: [1, 2, 3] }))
): WalletInterface {
  return {
    createSignature,
    createHmac: jest.fn(async () => ({ hmac: Array.from({ length: 32 }).fill(4) })),
    getPublicKey: jest.fn(async () => ({ publicKey: clientIdentityKey })),
    verifyHmac: jest.fn(async () => ({ valid: true })),
    verifySignature: jest.fn(async () => ({ valid: true }))
  } as unknown as WalletInterface
}

class AsyncTestSessionManager implements AsyncSessionManager {
  readonly sessions = new Map<string, PeerSession>()

  async addSession(session: PeerSession): Promise<void> {
    await Promise.resolve()
    this.sessions.set(session.sessionNonce as string, { ...session })
  }

  async updateSession(session: PeerSession): Promise<void> {
    await Promise.resolve()
    this.sessions.set(session.sessionNonce as string, { ...session })
  }

  async updateSessionIfUnauthenticated(session: PeerSession): Promise<boolean> {
    await Promise.resolve()
    const current = this.sessions.get(session.sessionNonce as string)
    if (current?.isAuthenticated !== false) return false
    this.sessions.set(session.sessionNonce as string, { ...session })
    return true
  }

  async getSession(identifier: string): Promise<PeerSession | undefined> {
    await Promise.resolve()
    const session = (
      this.sessions.get(identifier) ??
      [...this.sessions.values()].find(session => session.peerIdentityKey === identifier)
    )
    return session == null ? undefined : { ...session }
  }

  async removeSession(session: PeerSession): Promise<void> {
    await Promise.resolve()
    this.sessions.delete(session.sessionNonce as string)
  }

  async removeSessionIfUnauthenticated(sessionNonce: string): Promise<void> {
    await Promise.resolve()
    const session = this.sessions.get(sessionNonce)
    if (session?.isAuthenticated === false) {
      this.sessions.delete(sessionNonce)
    }
  }

  async hasSession(identifier: string): Promise<boolean> {
    return (await this.getSession(identifier)) != null
  }
}

async function makeAuthenticatedHarness(
  fetchClient: typeof fetch,
  wallet: WalletInterface = makeWallet()
): Promise<{
  authFetch: AuthFetch
  peer: Peer
  sessionManager: SessionManager
}> {
  const sessionManager = new SessionManager()
  sessionManager.addSession({
    isAuthenticated: true,
    sessionNonce,
    peerNonce: 'ERITFBUWFxgZGhscHR4fIA==',
    peerIdentityKey: serverIdentityKey,
    lastUpdate: Date.now(),
    certificatesRequired: false,
    certificatesValidated: true
  })
  const transport = new SimplifiedFetchTransport(baseUrl, fetchClient)
  const peer = new Peer(wallet, transport, undefined, sessionManager)
  await peer.ready
  const authFetch = new AuthFetch(wallet, undefined, sessionManager)
  authFetch.peers[baseUrl] = {
    peer,
    identityKey: serverIdentityKey,
    supportsMutualAuth: true,
    pendingCertificateRequests: []
  }
  return { authFetch, peer, sessionManager }
}

function expectSafeTimeout(error: unknown, dispatchState: string): void {
  expect(error).toBeInstanceOf(Error)
  expect((error as Error).message).toBe('Timed out waiting for authenticated response.')
  expect((error as any).details).toEqual({
    requestId: expect.any(String),
    dispatchState
  })
  expect(Object.keys((error as any).details)).toEqual(['requestId', 'dispatchState'])
}

describe('AuthFetch request deadline with real Peer and transport', () => {
  afterEach(() => {
    jest.useRealTimers()
    jest.restoreAllMocks()
  })

  test('late wallet approval is ignored and dispatches no application POST', async () => {
    jest.useFakeTimers()
    const approval = deferred<{ signature: number[] }>()
    const createSignature = jest.fn(() => approval.promise)
    const fetchClient = jest.fn<typeof fetch>()
    const { authFetch } = await makeAuthenticatedHarness(fetchClient, makeWallet(createSignature))

    const request = authFetch.fetch(`${baseUrl}/write`, {
      method: 'POST',
      body: 'synthetic request body'
    })
    const rejection = request.catch(error => error)
    await jest.advanceTimersByTimeAsync(0)
    expect(createSignature).toHaveBeenCalledTimes(1)

    await jest.advanceTimersByTimeAsync(30000)
    const timeout = await rejection
    expectSafeTimeout(timeout, 'not-dispatched')

    approval.resolve({ signature: [1, 2, 3] })
    await jest.advanceTimersByTimeAsync(0)
    expect(fetchClient).not.toHaveBeenCalled()
    expect((authFetch as any).pendingRequestNonces.size).toBe(0)
    expect(jest.getTimerCount()).toBe(0)
  })

  test('initial handshake timeout cleans up when custom send resolves without a response', async () => {
    jest.useFakeTimers()
    let handshakeSignal: AbortSignal | undefined
    const send = jest.fn(async (message: AuthMessage, signal?: AbortSignal) => {
      if (message.messageType !== 'initialRequest') throw new Error('unexpected general send')
      handshakeSignal = signal
    })
    const transport: Transport = {
      async onData(): Promise<void> {},
      send
    }
    const wallet = makeWallet()
    const sessionManager = new AsyncTestSessionManager()
    const peer = new Peer(wallet, transport, undefined, sessionManager)
    await peer.ready
    const authFetch = new AuthFetch(wallet, undefined, sessionManager)
    authFetch.peers[baseUrl] = {
      peer,
      supportsMutualAuth: true,
      pendingCertificateRequests: []
    }

    const rejection = authFetch.fetch(`${baseUrl}/write`, { method: 'POST' }).catch(error => error)
    await jest.advanceTimersByTimeAsync(0)
    expect(send).toHaveBeenCalledTimes(1)
    expect(sessionManager.sessions.size).toBe(1)
    expect((peer as any).onInitialResponseReceivedCallbacks.size).toBe(1)

    await jest.advanceTimersByTimeAsync(30000)
    expectSafeTimeout(await rejection, 'not-dispatched')
    await jest.advanceTimersByTimeAsync(0)

    expect(handshakeSignal?.aborted).toBe(true)
    expect(sessionManager.sessions.size).toBe(0)
    expect((peer as any).onInitialResponseReceivedCallbacks.size).toBe(0)
    expect((peer as any).initialResponseTasks.size).toBe(0)
    expect((peer as any).cancelledInitialResponseSessions.size).toBe(0)
    expect(send).toHaveBeenCalledTimes(1)
  })

  test('initial handshake timeout cleans up while custom send remains pending', async () => {
    jest.useFakeTimers()
    const sendGate = deferred<void>()
    const send = jest.fn(async () => await sendGate.promise)
    const transport: Transport = {
      async onData(): Promise<void> {},
      send
    }
    const wallet = makeWallet()
    const sessionManager = new AsyncTestSessionManager()
    const peer = new Peer(wallet, transport, undefined, sessionManager)
    await peer.ready
    const authFetch = new AuthFetch(wallet, undefined, sessionManager)
    authFetch.peers[baseUrl] = {
      peer,
      supportsMutualAuth: true,
      pendingCertificateRequests: []
    }

    const rejection = authFetch.fetch(`${baseUrl}/write`, { method: 'POST' }).catch(error => error)
    await jest.advanceTimersByTimeAsync(0)
    expect(send).toHaveBeenCalledTimes(1)
    expect(sessionManager.sessions.size).toBe(1)

    await jest.advanceTimersByTimeAsync(30000)
    expectSafeTimeout(await rejection, 'not-dispatched')
    await jest.advanceTimersByTimeAsync(0)

    expect(sessionManager.sessions.size).toBe(0)
    expect((peer as any).onInitialResponseReceivedCallbacks.size).toBe(0)
    expect((peer as any).initialResponseTasks.size).toBe(0)
    expect((peer as any).cancelledInitialResponseSessions.size).toBe(0)
    expect(send).toHaveBeenCalledTimes(1)

    sendGate.reject(new Error('late custom transport failure'))
    await jest.advanceTimersByTimeAsync(0)
  })

  test('initial handshake timeout wins after a valid response while send remains pending', async () => {
    jest.useFakeTimers()
    const sendGate = deferred<void>()
    const responseHandled = deferred<void>()
    let handshakeSignal: AbortSignal | undefined
    let onData: ((message: AuthMessage) => Promise<void>) | undefined
    const send = jest.fn(async (message: AuthMessage, signal?: AbortSignal) => {
      if (message.messageType !== 'initialRequest') throw new Error('unexpected general send')
      handshakeSignal = signal
      await onData?.({
        version: '0.1',
        messageType: 'initialResponse',
        identityKey: serverIdentityKey,
        initialNonce: 'ERITFBUWFxgZGhscHR4fIA==',
        yourNonce: message.initialNonce,
        signature: [1, 2, 3]
      })
      responseHandled.resolve(undefined)
      await sendGate.promise
    })
    const transport: Transport = {
      async onData(callback): Promise<void> {
        onData = callback
      },
      send
    }
    const wallet = makeWallet()
    const sessionManager = new AsyncTestSessionManager()
    const peer = new Peer(wallet, transport, undefined, sessionManager)
    await peer.ready
    const authFetch = new AuthFetch(wallet, undefined, sessionManager)
    authFetch.peers[baseUrl] = {
      peer,
      supportsMutualAuth: true,
      pendingCertificateRequests: []
    }

    const rejection = authFetch.fetch(`${baseUrl}/write`, { method: 'POST' }).catch(error => error)
    await responseHandled.promise
    expect([...sessionManager.sessions.values()]).toEqual([
      expect.objectContaining({ isAuthenticated: true })
    ])
    expect((peer as any).onInitialResponseReceivedCallbacks.size).toBe(0)

    await jest.advanceTimersByTimeAsync(30000)
    expectSafeTimeout(await rejection, 'not-dispatched')
    await jest.advanceTimersByTimeAsync(0)

    expect(handshakeSignal?.aborted).toBe(true)
    expect([...sessionManager.sessions.values()]).toEqual([
      expect.objectContaining({ isAuthenticated: true })
    ])
    expect((peer as any).initialResponseTasks.size).toBe(0)
    expect((peer as any).cancelledInitialResponseSessions.size).toBe(0)
    expect(send).toHaveBeenCalledTimes(1)

    sendGate.reject(new Error('late custom transport failure'))
    await jest.advanceTimersByTimeAsync(0)
  })

  test('handshake cleanup awaits concurrent authentication and preserves its session', async () => {
    const failure = new Error('transport failed after authentication completed')
    const sessionManager = new AsyncTestSessionManager()
    const verification = deferred<{ valid: boolean }>()
    let sessionNonce: string | undefined
    let onData: ((message: AuthMessage) => Promise<void>) | undefined
    let responseTask: Promise<void> | undefined
    const transport: Transport = {
      async onData(callback): Promise<void> {
        onData = callback
      },
      async send(message: AuthMessage): Promise<void> {
        sessionNonce = message.initialNonce
        responseTask = onData?.({
          version: '0.1',
          messageType: 'initialResponse',
          identityKey: serverIdentityKey,
          initialNonce: 'ERITFBUWFxgZGhscHR4fIA==',
          yourNonce: sessionNonce,
          signature: [1, 2, 3]
        })
        throw failure
      }
    }
    const wallet = makeWallet()
    ;(wallet.verifySignature as jest.Mock).mockImplementation(() => verification.promise)
    const peer = new Peer(wallet, transport, undefined, sessionManager)
    await peer.ready

    const sending = peer.toPeer([1, 2, 3])
    const rejected = expect(sending).rejects.toBe(failure)
    await new Promise(resolve => setTimeout(resolve, 0))
    expect(wallet.verifySignature).toHaveBeenCalledTimes(1)

    verification.resolve({ valid: true })
    await rejected
    await responseTask

    expect(sessionNonce).toEqual(expect.any(String))
    await expect(sessionManager.getSession(sessionNonce as string)).resolves.toMatchObject({
      isAuthenticated: true
    })
    expect((peer as any).onInitialResponseReceivedCallbacks.size).toBe(0)
    expect((peer as any).initialResponseTasks.size).toBe(0)
    expect((peer as any).cancelledInitialResponseSessions.size).toBe(0)
  })

  test('paired atomic transitions prevent cross-replica session resurrection', async () => {
    const sessionManager = new AsyncTestSessionManager()
    const sendGate = deferred<void>()
    const initialRequestSent = deferred<void>()
    const verification = deferred<{ valid: boolean }>()
    const verificationStarted = deferred<void>()
    let sessionNonce: string | undefined
    let onReplicaBData: ((message: AuthMessage) => Promise<void>) | undefined
    const replicaATransport: Transport = {
      async onData(): Promise<void> {},
      async send(message): Promise<void> {
        sessionNonce = message.initialNonce
        initialRequestSent.resolve(undefined)
        await sendGate.promise
      }
    }
    const replicaBTransport: Transport = {
      async onData(callback): Promise<void> {
        onReplicaBData = callback
      },
      async send(): Promise<void> {
        throw new Error('unexpected replica B send')
      }
    }
    const replicaBWallet = makeWallet()
    ;(replicaBWallet.verifySignature as jest.Mock).mockImplementation(() => {
      verificationStarted.resolve(undefined)
      return verification.promise
    })
    const replicaA = new Peer(makeWallet(), replicaATransport, undefined, sessionManager)
    const replicaB = new Peer(replicaBWallet, replicaBTransport, undefined, sessionManager)
    await Promise.all([replicaA.ready, replicaB.ready])
    const controller = new AbortController()
    const abortError = new Error('cancel replica A handshake')

    const sending = replicaA.toPeer([1, 2, 3], undefined, controller.signal)
    await initialRequestSent.promise
    const responseTask = onReplicaBData?.({
      version: '0.1',
      messageType: 'initialResponse',
      identityKey: serverIdentityKey,
      initialNonce: 'ERITFBUWFxgZGhscHR4fIA==',
      yourNonce: sessionNonce,
      signature: [1, 2, 3]
    }) as Promise<void>
    const responseRejection = expect(responseTask).rejects.toThrow(
      'Peer session is no longer pending'
    )
    await verificationStarted.promise

    controller.abort(abortError)
    await expect(sending).rejects.toBe(abortError)
    expect(sessionManager.sessions.size).toBe(0)

    verification.resolve({ valid: true })
    await responseRejection
    expect(sessionManager.sessions.size).toBe(0)
    expect((replicaA as any).initialResponseTasks.size).toBe(0)
    expect((replicaA as any).cancelledInitialResponseSessions.size).toBe(0)
    expect((replicaB as any).initialResponseTasks.size).toBe(0)

    sendGate.reject(new Error('late replica A transport failure'))
    await Promise.resolve()
  })

  test('handshake cleanup leaves legacy async store rows for safe maintenance', async () => {
    const sessions = new Map<string, PeerSession>()
    const removeSession = jest.fn(async (session: PeerSession) => {
      sessions.delete(session.sessionNonce as string)
    })
    const sessionManager: AsyncSessionManager = {
      async addSession(session): Promise<void> {
        sessions.set(session.sessionNonce as string, session)
      },
      async updateSession(session): Promise<void> {
        sessions.set(session.sessionNonce as string, session)
      },
      async getSession(identifier): Promise<PeerSession | undefined> {
        return sessions.get(identifier)
      },
      removeSession,
      async hasSession(identifier): Promise<boolean> {
        return sessions.has(identifier)
      }
    }
    const failure = new Error('initial send failed')
    const transport: Transport = {
      async onData(): Promise<void> {},
      async send(): Promise<void> {
        throw failure
      }
    }
    const peer = new Peer(makeWallet(), transport, undefined, sessionManager)
    await peer.ready

    await expect(peer.toPeer([1, 2, 3])).rejects.toBe(failure)

    expect(removeSession).not.toHaveBeenCalled()
    expect([...sessions.values()]).toEqual([
      expect.objectContaining({ isAuthenticated: false })
    ])
    expect((peer as any).onInitialResponseReceivedCallbacks.size).toBe(0)
    expect((peer as any).initialResponseTasks.size).toBe(0)
    expect((peer as any).cancelledInitialResponseSessions.size).toBe(0)
  })

  test.each([
    ['neither atomic method', false, false],
    ['only atomic update', true, false],
    ['only atomic removal', false, true]
  ])('cancellable handshake fails closed with a manager providing %s', async (
    _description,
    hasUpdate,
    hasRemoval
  ) => {
    const sessions = new Map<string, PeerSession>()
    const sessionManager: any = {
      addSession: jest.fn(async (session: PeerSession) => {
        sessions.set(session.sessionNonce as string, session)
      }),
      updateSession: jest.fn(async (session: PeerSession) => {
        sessions.set(session.sessionNonce as string, session)
      }),
      getSession: jest.fn(async (identifier: string) => sessions.get(identifier)),
      removeSession: jest.fn(async (session: PeerSession) => {
        sessions.delete(session.sessionNonce as string)
      }),
      hasSession: jest.fn(async (identifier: string) => sessions.has(identifier))
    }
    if (hasUpdate) {
      sessionManager.updateSessionIfUnauthenticated = jest.fn(async () => false)
    }
    if (hasRemoval) {
      sessionManager.removeSessionIfUnauthenticated = jest.fn(async () => {})
    }
    let onData: ((message: AuthMessage) => Promise<void>) | undefined
    const transport: Transport = {
      send: jest.fn(async () => {}),
      async onData(callback): Promise<void> {
        onData = callback
      }
    }
    const wallet = makeWallet() as any
    wallet.listCertificates = jest.fn()
    wallet.proveCertificate = jest.fn()
    const peer = new Peer(wallet, transport, undefined, sessionManager)
    await peer.ready
    const certificatesRequested = jest.fn()
    peer.listenForCertificatesRequested(certificatesRequested)
    const authFetch = new AuthFetch(wallet, undefined, sessionManager)
    authFetch.peers[baseUrl] = {
      peer,
      identityKey: serverIdentityKey,
      supportsMutualAuth: true,
      pendingCertificateRequests: []
    }

    await expect(authFetch.fetch(`${baseUrl}/write`)).rejects.toThrow(
      'Cancellable handshakes require a session manager implementing both updateSessionIfUnauthenticated and removeSessionIfUnauthenticated.'
    )
    expect(sessions.size).toBe(0)
    expect(sessionManager.addSession).not.toHaveBeenCalled()
    expect(sessionManager.updateSession).not.toHaveBeenCalled()
    expect(transport.send).not.toHaveBeenCalled()
    expect(wallet.createHmac).not.toHaveBeenCalled()
    expect(wallet.getPublicKey).not.toHaveBeenCalled()
    expect(wallet.verifyHmac).not.toHaveBeenCalled()
    expect(wallet.verifySignature).not.toHaveBeenCalled()
    expect(wallet.createSignature).not.toHaveBeenCalled()
    expect(wallet.listCertificates).not.toHaveBeenCalled()
    expect(wallet.proveCertificate).not.toHaveBeenCalled()
    expect(certificatesRequested).not.toHaveBeenCalled()

    await expect(onData?.({
      version: '0.1',
      messageType: 'initialResponse',
      identityKey: serverIdentityKey,
      initialNonce: 'ERITFBUWFxgZGhscHR4fIA==',
      yourNonce: 'late-session-nonce',
      requestedCertificates: {
        certifiers: [serverIdentityKey],
        types: { testType: ['name'] }
      },
      signature: [1, 2, 3]
    })).rejects.toThrow('Peer session not found')
    expect(sessions.size).toBe(0)
    expect(transport.send).not.toHaveBeenCalled()
    expect(wallet.verifyHmac).toHaveBeenCalledTimes(1)
    expect(wallet.verifySignature).not.toHaveBeenCalled()
    expect(wallet.listCertificates).not.toHaveBeenCalled()
    expect(certificatesRequested).not.toHaveBeenCalled()
    expect((authFetch as any).pendingRequestNonces.size).toBe(0)
  })

  test('invalid response cannot clear signal before valid response certificate approval', async () => {
    jest.useFakeTimers()
    const approval = deferred<any>()
    const approvalStarted = deferred<void>()
    const initialSend = deferred<void>()
    const requestedCertificates = {
      certifiers: [serverIdentityKey],
      types: { testType: ['name'] }
    }
    const wallet = makeWallet() as any
    wallet.verifySignature
      .mockResolvedValueOnce({ valid: false })
      .mockResolvedValue({ valid: true })
    wallet.listCertificates = jest.fn(() => {
      approvalStarted.resolve(undefined)
      return approval.promise
    })
    wallet.proveCertificate = jest.fn(async () => ({
      keyringForVerifier: { name: 'revealed-key' }
    }))
    let invalidResponseError: unknown
    const transportSend = jest
      .spyOn(SimplifiedFetchTransport.prototype, 'send')
      .mockImplementation(async function (
        this: SimplifiedFetchTransport,
        message: AuthMessage
      ): Promise<void> {
        if (message.messageType !== 'initialRequest') {
          throw new Error(`unexpected ${message.messageType} send`)
        }
        try {
          await (this as any).onDataCallback({
            version: '0.1',
            messageType: 'initialResponse',
            identityKey: serverIdentityKey,
            initialNonce: 'ERITFBUWFxgZGhscHR4fIA==',
            yourNonce: message.initialNonce,
            requestedCertificates,
            signature: [9, 9, 9]
          })
        } catch (error) {
          invalidResponseError = error
        }
        await (this as any).onDataCallback({
          version: '0.1',
          messageType: 'initialResponse',
          identityKey: serverIdentityKey,
          initialNonce: 'ERITFBUWFxgZGhscHR4fIA==',
          yourNonce: message.initialNonce,
          requestedCertificates,
          signature: [1, 2, 3]
        })
        await initialSend.promise
      })
    const authFetch = new AuthFetch(wallet)

    const rejection = authFetch.fetch(`${baseUrl}/write`, { method: 'POST' }).catch(error => error)
    await approvalStarted.promise
    const peerState = authFetch.peers[baseUrl]
    const peer = peerState.peer
    expect(invalidResponseError).toEqual(expect.objectContaining({
      message: expect.stringContaining('Unable to verify initial response signature')
    }))
    expect(wallet.verifySignature).toHaveBeenCalledTimes(2)
    expect(peerState.pendingCertificateRequests).toEqual([true])
    expect((peer as any).initialResponseTasks.size).toBe(0)
    expect((peer as any).initialResponseSignals.size).toBe(1)

    await jest.advanceTimersByTimeAsync(30000)
    expectSafeTimeout(await rejection, 'not-dispatched')
    expect((peer as any).initialResponseTasks.size).toBe(0)
    expect((peer as any).cancelledInitialResponseSessions.size).toBe(0)
    expect((peer as any).initialResponseSignals.size).toBe(0)

    approval.resolve({
      certificates: [{
        type: 'testType',
        serialNumber: 'serial',
        subject: clientIdentityKey,
        certifier: serverIdentityKey,
        revocationOutpoint: 'outpoint',
        fields: { name: 'value' },
        signature: [1, 2, 3]
      }]
    })
    await jest.advanceTimersByTimeAsync(0)
    expect(wallet.proveCertificate).toHaveBeenCalledTimes(1)
    expect(transportSend).toHaveBeenCalledTimes(1)
    expect(peerState.pendingCertificateRequests).toEqual([])
    expect((peer as any).initialResponseTasks.size).toBe(0)
    expect((peer as any).cancelledInitialResponseSessions.size).toBe(0)
    expect((peer as any).initialResponseSignals.size).toBe(0)
    expect(jest.getTimerCount()).toBe(0)

    initialSend.reject(new Error('late initial send failure'))
    await jest.advanceTimersByTimeAsync(0)
  })

  test('cancels the pending-certificate poll timer without dispatching', async () => {
    jest.useFakeTimers()
    const fetchClient = jest.fn<typeof fetch>()
    const { authFetch } = await makeAuthenticatedHarness(fetchClient)
    authFetch.peers[baseUrl].pendingCertificateRequests.push(true)

    const rejection = authFetch.fetch(`${baseUrl}/write`, { method: 'POST' }).catch(error => error)
    await jest.advanceTimersByTimeAsync(0)
    expect(jest.getTimerCount()).toBe(2)

    await jest.advanceTimersByTimeAsync(30000)
    expectSafeTimeout(await rejection, 'not-dispatched')
    expect(fetchClient).not.toHaveBeenCalled()
    expect((authFetch as any).pendingRequestNonces.size).toBe(0)
    expect(jest.getTimerCount()).toBe(0)
  })

  test('aborts one dispatched POST and reports its outcome as indeterminate', async () => {
    jest.useFakeTimers()
    let capturedSignal: AbortSignal | undefined
    const fetchClient = jest.fn<typeof fetch>(async (_input, init) => {
      capturedSignal = init?.signal ?? undefined
      return await new Promise<Response>((_resolve, reject) => {
        capturedSignal?.addEventListener('abort', () => reject(capturedSignal?.reason), {
          once: true
        })
      })
    })
    const { authFetch } = await makeAuthenticatedHarness(fetchClient)

    const rejection = authFetch.fetch(`${baseUrl}/write`, { method: 'POST' }).catch(error => error)
    await jest.advanceTimersByTimeAsync(0)
    expect(fetchClient).toHaveBeenCalledTimes(1)
    expect(capturedSignal?.aborted).toBe(false)

    await jest.advanceTimersByTimeAsync(30000)
    expectSafeTimeout(await rejection, 'possibly-dispatched')
    expect(fetchClient).toHaveBeenCalledTimes(1)
    expect(capturedSignal?.aborted).toBe(true)
    expect((authFetch as any).pendingRequestNonces.size).toBe(0)
    expect(jest.getTimerCount()).toBe(0)
  })

  test('a late transport failure neither resettles nor retries the write', async () => {
    jest.useFakeTimers()
    const lateResponse = deferred<Response>()
    const fetchClient = jest.fn<typeof fetch>(() => lateResponse.promise)
    const { authFetch } = await makeAuthenticatedHarness(fetchClient)
    const recursiveFetch = jest.spyOn(authFetch, 'fetch')

    const rejection = authFetch.fetch(`${baseUrl}/write`, { method: 'POST' }).catch(error => error)
    await jest.advanceTimersByTimeAsync(0)
    expect(fetchClient).toHaveBeenCalledTimes(1)

    await jest.advanceTimersByTimeAsync(30000)
    const timeout = await rejection
    expectSafeTimeout(timeout, 'possibly-dispatched')

    lateResponse.resolve(new Response('late gateway response', { status: 401 }))
    await jest.advanceTimersByTimeAsync(0)
    expect(recursiveFetch).toHaveBeenCalledTimes(1)
    expect(fetchClient).toHaveBeenCalledTimes(1)
    expect((authFetch as any).pendingRequestNonces.size).toBe(0)
  })

  test('stale-session recovery keeps prior dispatch state through the original deadline', async () => {
    jest.useFakeTimers()
    const staleFailure = deferred<void>()
    const recoveredPeer = deferred<any>()
    const staleError = new Error('Session not found for nonce: stale')
    const firstToPeer = jest.fn(async (
      _message: number[],
      _identityKey?: string,
      _signal?: AbortSignal,
      onDispatch?: () => void
    ) => {
      onDispatch?.()
      await staleFailure.promise
      throw staleError
    })
    const retryToPeer = jest.fn(async () => {})
    const firstPeer = {
      peer: {
        listenForGeneralMessages: jest.fn(() => 1),
        stopListeningForGeneralMessages: jest.fn(),
        toPeer: firstToPeer
      },
      identityKey: serverIdentityKey,
      supportsMutualAuth: true,
      pendingCertificateRequests: []
    }
    const retryPeer = {
      peer: {
        listenForGeneralMessages: jest.fn(() => 2),
        stopListeningForGeneralMessages: jest.fn(),
        toPeer: retryToPeer
      },
      identityKey: serverIdentityKey,
      supportsMutualAuth: true,
      pendingCertificateRequests: []
    }
    const authFetch = new AuthFetch(makeWallet())
    const getOrCreatePeer = jest
      .spyOn(authFetch as any, 'getOrCreatePeer')
      .mockResolvedValueOnce(firstPeer)
      .mockImplementationOnce(async () => await recoveredPeer.promise)

    const rejection = authFetch.fetch(`${baseUrl}/write`, { method: 'POST' }).catch(error => error)
    await jest.advanceTimersByTimeAsync(29999)
    staleFailure.resolve(undefined)
    await jest.advanceTimersByTimeAsync(0)
    expect(getOrCreatePeer).toHaveBeenCalledTimes(2)
    expect(retryToPeer).not.toHaveBeenCalled()

    await jest.advanceTimersByTimeAsync(1)
    expectSafeTimeout(await rejection, 'possibly-dispatched')

    recoveredPeer.resolve(retryPeer)
    await jest.advanceTimersByTimeAsync(0)
    expect(retryToPeer).not.toHaveBeenCalled()
    expect((authFetch as any).pendingRequestNonces.size).toBe(0)
  })

  test('unauthenticated fallback is bounded by the original deadline', async () => {
    jest.useFakeTimers()
    const authenticationFailure = deferred<void>()
    const fallbackResult = deferred<Response>()
    let fallbackSignal: AbortSignal | undefined
    const fallback = jest.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => {
      fallbackSignal = init?.signal ?? undefined
      // Deliberately ignore cancellation to prove the SDK deadline still settles.
      return fallbackResult.promise
    })
    const peerState = {
      peer: {
        listenForGeneralMessages: jest.fn(() => 1),
        stopListeningForGeneralMessages: jest.fn(),
        toPeer: jest.fn(async () => {
          await authenticationFailure.promise
          throw new Error('HTTP server failed to authenticate')
        })
      },
      identityKey: serverIdentityKey,
      supportsMutualAuth: true,
      pendingCertificateRequests: []
    }
    const authFetch = new AuthFetch(makeWallet())
    jest.spyOn(authFetch as any, 'getOrCreatePeer').mockResolvedValue(peerState)

    const rejection = authFetch.fetch(`${baseUrl}/write`, { method: 'POST' }).catch(error => error)
    await jest.advanceTimersByTimeAsync(29999)
    authenticationFailure.resolve(undefined)
    await jest.advanceTimersByTimeAsync(0)
    expect(fallback).toHaveBeenCalledTimes(1)
    expect(fallbackSignal?.aborted).toBe(false)

    await jest.advanceTimersByTimeAsync(1)
    expectSafeTimeout(await rejection, 'possibly-dispatched')
    expect(fallbackSignal?.aborted).toBe(true)
    expect(fallback).toHaveBeenCalledTimes(1)
    expect((authFetch as any).pendingRequestNonces.size).toBe(0)

    fallbackResult.reject(new Error('late fallback failure'))
    await jest.advanceTimersByTimeAsync(0)
  })

  test('classifies a cancellation-ignoring custom transport as possibly dispatched', async () => {
    jest.useFakeTimers()
    const delayedDispatch = deferred<void>()
    let capturedSignal: AbortSignal | undefined
    let sideEffects = 0
    const transport: Transport = {
      async onData(): Promise<void> {},
      async send(message: AuthMessage, signal?: AbortSignal): Promise<void> {
        if (message.messageType !== 'general') throw new Error('unexpected handshake')
        capturedSignal = signal
        await delayedDispatch.promise
        // Deliberately violates the documented custom-transport contract by
        // ignoring the aborted signal before its side effect.
        sideEffects++
      }
    }
    const wallet = makeWallet()
    const sessionManager = new SessionManager()
    sessionManager.addSession({
      isAuthenticated: true,
      sessionNonce,
      peerNonce: 'ERITFBUWFxgZGhscHR4fIA==',
      peerIdentityKey: serverIdentityKey,
      lastUpdate: Date.now()
    })
    const peer = new Peer(wallet, transport, undefined, sessionManager)
    await peer.ready
    const authFetch = new AuthFetch(wallet, undefined, sessionManager)
    authFetch.peers[baseUrl] = {
      peer,
      identityKey: serverIdentityKey,
      supportsMutualAuth: true,
      pendingCertificateRequests: []
    }
    const fetchCalls = jest.spyOn(authFetch, 'fetch')

    const rejection = authFetch.fetch(`${baseUrl}/write`, { method: 'POST' }).catch(error => error)
    await jest.advanceTimersByTimeAsync(0)
    expect(capturedSignal?.aborted).toBe(false)

    await jest.advanceTimersByTimeAsync(30000)
    expectSafeTimeout(await rejection, 'possibly-dispatched')
    expect(capturedSignal?.aborted).toBe(true)
    expect(sideEffects).toBe(0)

    delayedDispatch.resolve()
    await jest.advanceTimersByTimeAsync(0)
    expect(sideEffects).toBe(1)
    expect(fetchCalls).toHaveBeenCalledTimes(1)
    expect((authFetch as any).pendingRequestNonces.size).toBe(0)
  })

  test('a cancellation-aware delayed custom transport suppresses its late side effect', async () => {
    jest.useFakeTimers()
    const delayedDispatch = deferred<void>()
    let capturedSignal: AbortSignal | undefined
    let sideEffects = 0
    const transport: Transport = {
      async onData(): Promise<void> {},
      async send(message: AuthMessage, signal?: AbortSignal): Promise<void> {
        if (message.messageType !== 'general') throw new Error('unexpected handshake')
        capturedSignal = signal
        await delayedDispatch.promise
        signal?.throwIfAborted()
        sideEffects++
      }
    }
    const wallet = makeWallet()
    const sessionManager = new SessionManager()
    sessionManager.addSession({
      isAuthenticated: true,
      sessionNonce,
      peerNonce: 'ERITFBUWFxgZGhscHR4fIA==',
      peerIdentityKey: serverIdentityKey,
      lastUpdate: Date.now()
    })
    const peer = new Peer(wallet, transport, undefined, sessionManager)
    await peer.ready
    const authFetch = new AuthFetch(wallet, undefined, sessionManager)
    authFetch.peers[baseUrl] = {
      peer,
      identityKey: serverIdentityKey,
      supportsMutualAuth: true,
      pendingCertificateRequests: []
    }
    const fetchCalls = jest.spyOn(authFetch, 'fetch')

    const rejection = authFetch.fetch(`${baseUrl}/write`, { method: 'POST' }).catch(error => error)
    await jest.advanceTimersByTimeAsync(0)
    expect(capturedSignal?.aborted).toBe(false)

    await jest.advanceTimersByTimeAsync(30000)
    expectSafeTimeout(await rejection, 'possibly-dispatched')
    expect(capturedSignal?.aborted).toBe(true)

    delayedDispatch.resolve()
    await jest.advanceTimersByTimeAsync(0)
    expect(sideEffects).toBe(0)
    expect(fetchCalls).toHaveBeenCalledTimes(1)
    expect((authFetch as any).pendingRequestNonces.size).toBe(0)
  })

  test('wallet denial is preserved and never reaches fetch', async () => {
    const denial = new Error('user denied signing approval')
    const createSignature = jest.fn(async () => await Promise.reject(denial))
    const fetchClient = jest.fn<typeof fetch>()
    const { authFetch } = await makeAuthenticatedHarness(fetchClient, makeWallet(createSignature))

    await expect(authFetch.fetch(`${baseUrl}/write`, { method: 'POST' })).rejects.toBe(denial)
    expect(fetchClient).not.toHaveBeenCalled()
    expect((authFetch as any).pendingRequestNonces.size).toBe(0)
  })

  test('legacy AbortSignal shapes work without throwIfAborted', async () => {
    const transport: Transport = {
      send: jest.fn(async () => {}),
      async onData(): Promise<void> {}
    }
    const sessionManager = new SessionManager()
    sessionManager.addSession({
      isAuthenticated: true,
      sessionNonce,
      peerNonce: 'ERITFBUWFxgZGhscHR4fIA==',
      peerIdentityKey: serverIdentityKey,
      lastUpdate: Date.now()
    })
    const peer = new Peer(makeWallet(), transport, undefined, sessionManager)
    await peer.ready
    const activeSignal = {
      aborted: false,
      reason: undefined,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn()
    } as unknown as AbortSignal

    await expect(
      peer.toPeer([1, 2, 3], serverIdentityKey, activeSignal)
    ).resolves.toBeUndefined()

    const abortError = new Error('legacy signal aborted')
    const abortedSignal = {
      aborted: true,
      reason: abortError,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn()
    } as unknown as AbortSignal
    await expect(
      peer.toPeer([1, 2, 3], serverIdentityKey, abortedSignal)
    ).rejects.toBe(abortError)
    expect(transport.send).toHaveBeenCalledTimes(1)
  })

  test('legacy Transport and Peer.toPeer calls remain compatible', async () => {
    class LegacyTransport implements Transport {
      sent: AuthMessage[] = []

      async send(message: AuthMessage): Promise<void> {
        this.sent.push(message)
      }

      async onData(_callback: (message: AuthMessage) => Promise<void>): Promise<void> {}
    }

    const sessionManager = new SessionManager()
    sessionManager.addSession({
      isAuthenticated: true,
      sessionNonce,
      peerNonce: 'ERITFBUWFxgZGhscHR4fIA==',
      peerIdentityKey: serverIdentityKey,
      lastUpdate: Date.now()
    })
    const transport = new LegacyTransport()
    const peer = new Peer(makeWallet(), transport, undefined, sessionManager)
    await peer.ready

    await expect(peer.toPeer([7, 8, 9], serverIdentityKey)).resolves.toBeUndefined()
    expect(transport.sent).toHaveLength(1)
    expect(transport.sent[0]).toMatchObject({ messageType: 'general', payload: [7, 8, 9] })
  })
})
