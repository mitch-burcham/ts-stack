import { jest } from '@jest/globals'
import PrivateKey from '../../primitives/PrivateKey.js'
import * as Utils from '../../primitives/utils.js'
import { Peer } from '../Peer.js'
import { assertRequestedCertificateSet, assertValidAuthMessage } from '../AuthMessageValidation.js'
import { SessionManager } from '../SessionManager.js'
import type { AuthMessage } from '../types.js'

const identityKey = new PrivateKey(40).toPublicKey().toString()
const sessionNonce = Utils.toBase64(Array(48).fill(1))
const messageNonce = Utils.toBase64(Array(32).fill(2))

function general(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: '0.1',
    messageType: 'general',
    identityKey,
    nonce: messageNonce,
    yourNonce: sessionNonce,
    payload: [],
    signature: [1],
    ...overrides
  }
}

describe('BRC-103 untrusted message validation', () => {
  test('accepts a canonical general-message shape', () => {
    expect(() => assertValidAuthMessage(general())).not.toThrow()
  })

  test.each([
    ['invalid identity', { identityKey: `02${'00'.repeat(32)}` }],
    ['noncanonical message nonce', { nonce: `${messageNonce}\n` }],
    ['wrong session nonce width', { yourNonce: messageNonce }],
    ['sparse payload', { payload: Object.assign(Array(2), { 1: 1 }) }],
    ['oversized signature', { signature: Array(1025).fill(1) }],
    ['non-byte signature', { signature: [1, 256] }]
  ])('rejects %s before wallet processing', (_label, override) => {
    expect(() => assertValidAuthMessage(general(override))).toThrow()
  })

  test('rejects deep and prototype-sensitive object graphs without invoking accessors', () => {
    let deep: Record<string, unknown> = {}
    const root = deep
    for (let index = 0; index < 65; index++) {
      deep.next = {}
      deep = deep.next as Record<string, unknown>
    }
    expect(() => assertValidAuthMessage(general({ extra: root }))).toThrow('structure')

    const getter = jest.fn(() => '0.1')
    const message = general()
    Object.defineProperty(message, 'extra', { enumerable: true, get: getter })
    expect(() => assertValidAuthMessage(message)).toThrow('accessors')
    expect(getter).not.toHaveBeenCalled()

    const unsafe = JSON.parse(
      `{"version":"0.1","messageType":"general","identityKey":"${identityKey}","nonce":"${messageNonce}","yourNonce":"${sessionNonce}","payload":[],"signature":[1],"__proto__":true}`
    )
    expect(() => assertValidAuthMessage(unsafe)).toThrow('unsafe')

    const { version: _version, ...withoutOwnVersion } = general()
    const inheritedVersion = Object.assign(
      Object.create({ version: '0.1' }) as Record<string, unknown>,
      withoutOwnVersion
    )
    expect(() => assertValidAuthMessage(inheritedVersion)).toThrow('version')
  })

  test('owns an incoming message before asynchronous signature verification', async () => {
    let receive!: (message: AuthMessage) => Promise<void>
    let verificationStarted!: () => void
    let releaseVerification!: () => void
    const started = new Promise<void>(resolve => {
      verificationStarted = resolve
    })
    const blocked = new Promise<void>(resolve => {
      releaseVerification = resolve
    })
    const transport = {
      send: jest.fn(async () => {}),
      onData: jest.fn((callback: (message: AuthMessage) => Promise<void>) => {
        receive = callback
        return Promise.resolve()
      })
    }
    const wallet = {
      verifyHmac: jest.fn(async () => ({ valid: true })),
      verifySignature: jest.fn(async ({ data }: { data: number[] }) => {
        expect(data).toEqual([1])
        verificationStarted()
        await blocked
        return { valid: true }
      })
    }
    const sessions = new SessionManager()
    sessions.addSession({
      isAuthenticated: true,
      sessionNonce,
      peerNonce: sessionNonce,
      peerIdentityKey: identityKey,
      lastUpdate: Date.now(),
      certificatesRequired: false,
      certificatesValidated: true
    })
    const peer = new Peer(wallet as never, transport as never, undefined, sessions)
    await peer.ready
    const locallySelectedPeer = new PrivateKey(42).toPublicKey().toString()
    ;(peer as any).lastInteractedWithPeer = locallySelectedPeer
    const delivered = jest.fn()
    peer.listenForGeneralMessages(delivered)
    const message = general({ payload: [1] }) as unknown as AuthMessage

    const processing = receive(message)
    await started
    message.payload![0] = 9
    releaseVerification()
    await processing

    expect(delivered).toHaveBeenCalledWith(identityKey, [1])
    expect((peer as any).lastInteractedWithPeer).toBe(locallySelectedPeer)
  })

  test('owns an outgoing payload before awaiting its wallet signature', async () => {
    let signingStarted!: () => void
    let releaseSigning!: () => void
    const started = new Promise<void>(resolve => {
      signingStarted = resolve
    })
    const blocked = new Promise<void>(resolve => {
      releaseSigning = resolve
    })
    const transport = { onData: jest.fn(() => Promise.resolve()), send: jest.fn(async () => {}) }
    const wallet = {
      createSignature: jest.fn(async ({ data }: { data: number[] }) => {
        expect(data).toEqual([1])
        signingStarted()
        await blocked
        return { signature: [1] }
      }),
      getPublicKey: jest.fn(async () => ({ publicKey: identityKey }))
    }
    const sessions = new SessionManager()
    const counterparty = new PrivateKey(41).toPublicKey().toString()
    sessions.addSession({
      isAuthenticated: true,
      sessionNonce,
      peerNonce: sessionNonce,
      peerIdentityKey: counterparty,
      lastUpdate: Date.now(),
      certificatesRequired: false,
      certificatesValidated: true
    })
    const peer = new Peer(wallet as never, transport as never, undefined, sessions)
    await peer.ready
    const payload = [1]

    const sending = peer.toPeer(payload, counterparty)
    await started
    payload[0] = 9
    releaseSigning()
    await sending

    expect(transport.send).toHaveBeenCalledWith(
      expect.objectContaining({ payload: [1] }),
      undefined
    )
  })

  test('rejects unsafe local policies and payloads before transport or wallet work', async () => {
    const transport = { onData: jest.fn(() => Promise.resolve()), send: jest.fn() }
    const wallet = { createSignature: jest.fn() }
    const peer = new Peer(wallet as never, transport as never)

    await expect(peer.toPeer([1, 256])).rejects.toThrow('dense byte array')
    expect(wallet.createSignature).not.toHaveBeenCalled()
    expect(transport.send).not.toHaveBeenCalled()

    const duplicatedCertifierPolicy = {
      certifiers: [identityKey, identityKey],
      types: {}
    }
    expect(() => assertRequestedCertificateSet(duplicatedCertifierPolicy)).toThrow('unique')
    expect(() => new Peer(wallet as never, transport as never, duplicatedCertifierPolicy)).toThrow(
      'unique'
    )

    const inheritedPolicy = Object.create({ inherited: true }) as Record<string, unknown>
    inheritedPolicy.certifiers = []
    inheritedPolicy.types = {}
    expect(() => assertRequestedCertificateSet(inheritedPolicy)).toThrow('plain object')
  })
})
