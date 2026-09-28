import { jest } from '@jest/globals'

import { Peer } from '../Peer.js'
import { AuthMessage, Transport } from '../types.js'
import { PrivateKey } from '../../primitives/index.js'
import { CompletedProtoWallet } from '../certificates/__tests/CompletedProtoWallet.js'
import { SessionManager } from '../SessionManager.js'

describe('Peer handshake callback boundary', () => {
  test('registers and cleans the initial-response waiter around a synchronous send failure', async () => {
    let peer: Peer
    const transport: Transport = {
      async send(message) {
        if (message.messageType === 'initialRequest') {
          expect((peer as any).onInitialResponseReceivedCallbacks.size).toBe(2)
          throw new Error('synchronous transport failure')
        }
      },
      async onData(_callback: (message: AuthMessage) => Promise<void>) {}
    }
    peer = new Peer(new CompletedProtoWallet(new PrivateKey(30)), transport)
    await peer.ready
    void (peer as any).waitForInitialResponse('unrelated-session')

    await expect(
      peer.getAuthenticatedSession(new PrivateKey(31).toPublicKey().toString())
    ).rejects.toThrow('synchronous transport failure')
    expect((peer as any).onInitialResponseReceivedCallbacks.size).toBe(1)
    expect(
      Array.from((peer as any).onInitialResponseReceivedCallbacks.values())[0].sessionNonce
    ).toBe('unrelated-session')
    ;(peer as any).stopListeningForInitialResponsesByNonce('unrelated-session')
    expect((peer as any).onInitialResponseReceivedCallbacks.size).toBe(0)
  })

  test('does not leak a waiter when transport send rejects asynchronously', async () => {
    const transport: Transport = {
      send: jest.fn(async () => await Promise.reject(new Error('asynchronous transport failure'))),
      async onData(_callback: (message: AuthMessage) => Promise<void>) {}
    }
    const peer = new Peer(new CompletedProtoWallet(new PrivateKey(32)), transport)
    await peer.ready

    await expect(
      peer.getAuthenticatedSession(new PrivateKey(33).toPublicKey().toString())
    ).rejects.toThrow('asynchronous transport failure')
    expect((peer as any).onInitialResponseReceivedCallbacks.size).toBe(0)
  })

  test('rejects a handshake that completes without a response nonce', async () => {
    const transport: Transport = {
      async send() {},
      async onData(_callback: (message: AuthMessage) => Promise<void>) {}
    }
    const peer = new Peer(new CompletedProtoWallet(new PrivateKey(40)), transport)
    await peer.ready
    jest.spyOn(peer as any, 'waitForInitialResponse').mockResolvedValue(undefined)

    await expect(
      (peer as any).initiateHandshake(new PrivateKey(41).toPublicKey().toString())
    ).rejects.toThrow('Initial response session nonce is required.')
    expect((peer as any).onInitialResponseReceivedCallbacks.size).toBe(0)
  })

  test('uses a safe default error when a cancellation signal has no reason', async () => {
    let abortListener: (() => void) | undefined
    let signalRegistered!: () => void
    const registered = new Promise<void>(resolve => {
      signalRegistered = resolve
    })
    const addEventListener = jest.fn(
      (_type: string, listener: EventListenerOrEventListenerObject) => {
        abortListener = listener as () => void
        signalRegistered()
      }
    )
    const removeEventListener = jest.fn()
    const signal = {
      aborted: false,
      reason: undefined,
      addEventListener,
      removeEventListener
    } as unknown as AbortSignal
    const transport: Transport = {
      async send() {
        await new Promise<void>(() => {})
      },
      async onData(_callback: (message: AuthMessage) => Promise<void>) {}
    }
    const peer = new Peer(new CompletedProtoWallet(new PrivateKey(38)), transport)
    await peer.ready

    const handshake = peer.getAuthenticatedSession(
      new PrivateKey(39).toPublicKey().toString(),
      signal
    )
    await registered
    expect(abortListener).toEqual(expect.any(Function))

    abortListener?.()

    await expect(handshake).rejects.toThrow('The operation was aborted.')
    expect(removeEventListener).toHaveBeenCalledWith('abort', expect.any(Function))
    expect((peer as any).onInitialResponseReceivedCallbacks.size).toBe(0)
  })

  test('removes the exact failed session after the initial send rejects', async () => {
    const failure = new Error('transport failed after session allocation')
    const transport: Transport = {
      async send() {
        throw failure
      },
      async onData(_callback: (message: AuthMessage) => Promise<void>) {}
    }
    const sessions = new SessionManager()
    const removeSession = jest.spyOn(sessions, 'removeSession')
    const peer = new Peer(
      new CompletedProtoWallet(new PrivateKey(34)),
      transport,
      undefined,
      sessions
    )
    await peer.ready

    await expect(
      peer.getAuthenticatedSession(new PrivateKey(35).toPublicKey().toString())
    ).rejects.toBe(failure)
    expect(removeSession).toHaveBeenCalledTimes(1)
    expect(removeSession.mock.calls[0]![0]).toMatchObject({ isAuthenticated: false })
  })

  test('does not remove an absent failed session', async () => {
    const removeSession = jest.fn(async () => {})
    const sessions = {
      addSession: jest.fn(async () => {}),
      updateSession: jest.fn(async () => {}),
      getSession: jest.fn(async () => undefined),
      removeSession,
      hasSession: jest.fn(async () => false),
      claimMessageNonce: jest.fn(async () => true),
      claimInitialRequestNonce: jest.fn(async () => true)
    }
    const transport: Transport = {
      async send() {
        throw new Error('transport failed without persisted session')
      },
      async onData(_callback: (message: AuthMessage) => Promise<void>) {}
    }
    const peer = new Peer(
      new CompletedProtoWallet(new PrivateKey(36)),
      transport,
      undefined,
      sessions
    )
    await peer.ready

    await expect(
      peer.getAuthenticatedSession(new PrivateKey(37).toPublicKey().toString())
    ).rejects.toThrow('transport failed without persisted session')
    expect(removeSession).not.toHaveBeenCalled()
  })
})
