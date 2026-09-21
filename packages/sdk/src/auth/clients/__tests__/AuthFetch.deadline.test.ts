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
    this.sessions.set(session.sessionNonce as string, session)
  }

  async updateSession(session: PeerSession): Promise<void> {
    await Promise.resolve()
    this.sessions.set(session.sessionNonce as string, session)
  }

  async getSession(identifier: string): Promise<PeerSession | undefined> {
    await Promise.resolve()
    return (
      this.sessions.get(identifier) ??
      [...this.sessions.values()].find(session => session.peerIdentityKey === identifier)
    )
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
