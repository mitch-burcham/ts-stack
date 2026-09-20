import { jest } from '@jest/globals'

import { Peer } from '../../Peer.js'
import { SessionManager } from '../../SessionManager.js'
import { AuthMessage, Transport } from '../../types.js'
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
    getPublicKey: jest.fn(async () => ({ publicKey: clientIdentityKey })),
    verifyHmac: jest.fn(async () => ({ valid: true })),
    verifySignature: jest.fn(async () => ({ valid: true }))
  } as unknown as WalletInterface
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
