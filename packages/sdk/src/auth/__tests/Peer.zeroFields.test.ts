import { jest } from '@jest/globals'
import { Peer } from '../Peer.js'
import { AuthMessage, PeerSession, Transport } from '../types.js'
import { AsyncSessionManager, SessionManager } from '../SessionManager.js'
import { MasterCertificate } from '../certificates/MasterCertificate.js'
import { VerifiableCertificate } from '../certificates/VerifiableCertificate.js'
import { CompletedProtoWallet } from '../certificates/__tests/CompletedProtoWallet.js'
import { PrivateKey, Utils } from '../../primitives/index.js'
import { WalletInterface } from '../../wallet/Wallet.interfaces.js'

// Delivers JSON wire messages through the real Peer listener, with no mocked
// signatures, nonces, certificate validation, or getVerifiableCertificates.
class QueuedTransport implements Transport {
  rewrite?: (message: AuthMessage) => void
  private receive?: (message: AuthMessage) => Promise<void>
  private readonly messages: AuthMessage[] = []
  private waiter?: (message: AuthMessage) => void

  async send(message: AuthMessage): Promise<void> {
    this.rewrite?.(message)
    const wire: AuthMessage = JSON.parse(JSON.stringify(message))
    if (this.waiter !== undefined) {
      const resolve = this.waiter
      this.waiter = undefined
      resolve(wire)
    } else {
      this.messages.push(wire)
    }
  }

  async onData(callback: (message: AuthMessage) => Promise<void>): Promise<void> {
    this.receive = callback
  }

  async next(): Promise<AuthMessage> {
    const message = this.messages.shift()
    if (message !== undefined) return message
    return await new Promise(resolve => {
      this.waiter = resolve
    })
  }

  async deliver(message: AuthMessage): Promise<void> {
    if (this.receive === undefined) throw new Error('Transport is not listening')
    await this.receive(message)
  }
}

// Exercise an external-store-shaped round trip, rather than relying on shared
// object identity in the default SessionManager.
class SerializedSessionStore implements AsyncSessionManager {
  private readonly sessions = new SessionManager()

  constructor(private readonly dropSnapshot = false) {}

  private copy(session: PeerSession): PeerSession {
    const stored: PeerSession = JSON.parse(JSON.stringify(session))
    if (this.dropSnapshot) delete stored.certificatePolicy
    return stored
  }

  async addSession(session: PeerSession): Promise<void> {
    this.sessions.addSession(this.copy(session))
  }

  async updateSession(session: PeerSession): Promise<void> {
    this.sessions.updateSession(this.copy(session))
  }

  async getSession(identifier: string): Promise<PeerSession | undefined> {
    const session = this.sessions.getSession(identifier)
    return session === undefined ? undefined : JSON.parse(JSON.stringify(session))
  }

  async removeSession(session: PeerSession): Promise<void> {
    this.sessions.removeSession(session)
  }

  async hasSession(identifier: string): Promise<boolean> {
    return this.sessions.hasSession(identifier)
  }

  async claimMessageNonce(sessionNonce: string, messageNonce: string): Promise<boolean> {
    return this.sessions.claimMessageNonce(sessionNonce, messageNonce)
  }

  async claimInitialRequestNonce(identityKey: string, initialNonce: string): Promise<boolean> {
    return this.sessions.claimInitialRequestNonce(identityKey, initialNonce)
  }
}

// Simulates another replica winning the authentication CAS after this Peer
// reads the pending row but before it attempts its own transition.
class AuthenticationCasConflictStore implements AsyncSessionManager {
  private readonly sessions = new SessionManager()

  constructor(private readonly policyState: 'matching' | 'dropped' | 'changed') {}

  private copy(session: PeerSession): PeerSession {
    return JSON.parse(JSON.stringify(session))
  }

  async addSession(session: PeerSession): Promise<void> {
    this.sessions.addSession(this.copy(session))
  }

  async updateSession(session: PeerSession): Promise<void> {
    this.sessions.updateSession(this.copy(session))
  }

  async updateSessionIfUnauthenticated(session: PeerSession): Promise<boolean> {
    const competingSession = this.copy(session)
    if (this.policyState === 'dropped') {
      delete competingSession.certificatePolicy
    } else if (this.policyState === 'changed' && competingSession.certificatePolicy != null) {
      competingSession.certificatePolicy = {
        certifiers: [...competingSession.certificatePolicy.certifiers],
        types: Object.fromEntries(
          Object.keys(competingSession.certificatePolicy.types).map(type => [type, ['name']])
        )
      }
    }
    this.sessions.updateSession(competingSession)
    return false
  }

  async getSession(identifier: string): Promise<PeerSession | undefined> {
    const session = this.sessions.getSession(identifier)
    return session === undefined ? undefined : this.copy(session)
  }

  async removeSession(session: PeerSession): Promise<void> {
    this.sessions.removeSession(session)
  }

  async removeSessionIfUnauthenticated(sessionNonce: string): Promise<void> {
    this.sessions.removeSessionIfUnauthenticated(sessionNonce)
  }

  async hasSession(identifier: string): Promise<boolean> {
    return this.sessions.hasSession(identifier)
  }

  async claimMessageNonce(sessionNonce: string, messageNonce: string): Promise<boolean> {
    return this.sessions.claimMessageNonce(sessionNonce, messageNonce)
  }

  async claimInitialRequestNonce(identityKey: string, initialNonce: string): Promise<boolean> {
    return this.sessions.claimInitialRequestNonce(identityKey, initialNonce)
  }
}

async function peers(
  fields: string[] = [],
  store: 'sync' | 'async' | 'legacy' | 'cas-matching' | 'cas-dropped' | 'cas-changed' = 'sync',
  requireCertificates = true
) {
  const issuer = new CompletedProtoWallet(new PrivateKey(81))
  const holder = new CompletedProtoWallet(new PrivateKey(82))
  const verifier = new CompletedProtoWallet(new PrivateKey(83))
  const holderIdentity = (await holder.getPublicKey({ identityKey: true })).publicKey
  const verifierIdentity = (await verifier.getPublicKey({ identityKey: true })).publicKey
  const master = await MasterCertificate.issueCertificateForSubject(
    issuer,
    holderIdentity,
    { name: 'Synthetic peer' },
    Utils.toBase64(Array.from({ length: 32 }, () => 8)),
    async () => `${'34'.repeat(32)}.0`
  )
  if (master.signature === undefined) throw new Error('Expected an issuer-signed fixture')
  const signedMaster = Object.assign(master, { signature: master.signature })
  const requested = { certifiers: [master.certifier], types: { [master.type]: fields } }
  // Storage and permission are fixture doubles. The exact prove call remains
  // observable; production wallet-toolbox/DCAP integration is a separate test.
  const proveCertificate = jest.fn<
    ReturnType<WalletInterface['proveCertificate']>,
    Parameters<WalletInterface['proveCertificate']>
  >(async args => ({
    keyringForVerifier: await MasterCertificate.createKeyringForVerifier(
      holder,
      master.certifier,
      args.verifier,
      master.fields,
      args.fieldsToReveal,
      master.masterKeyring,
      master.serialNumber
    )
  }))
  const holderWallet: WalletInterface = Object.assign(holder, {
    listCertificates: jest.fn(async () => ({ totalCertificates: 1, certificates: [master] })),
    proveCertificate
  })
  const verifierTransport = new QueuedTransport()
  const holderTransport = new QueuedTransport()
  const verifierSessionManager = store.startsWith('cas-')
    ? new AuthenticationCasConflictStore(
        store.slice('cas-'.length) as 'matching' | 'dropped' | 'changed'
      )
    : store === 'sync'
      ? undefined
      : new SerializedSessionStore(store === 'legacy')
  const verifierPeer = new Peer(
    verifier,
    verifierTransport,
    requireCertificates ? requested : undefined,
    verifierSessionManager
  )
  const holderPeer = new Peer(holderWallet, holderTransport)
  await Promise.all([verifierPeer.ready, holderPeer.ready])
  const certificatesReceived = jest.fn()
  verifierPeer.listenForCertificatesReceived(certificatesReceived)
  const decrypt = jest.spyOn(verifier, 'decrypt')
  return {
    verifierPeer,
    holderPeer,
    verifierTransport,
    holderTransport,
    holderIdentity,
    verifierIdentity,
    master: signedMaster,
    requested,
    proveCertificate,
    certificatesReceived,
    decrypt,
    issuer,
    holder,
    verifier
  }
}

// A freshly signed second initialResponse for the same session: upstream claims each
// initialNonce once, so a new nonce and signature pass transport authentication again.
async function secondInitialResponse(
  f: Awaited<ReturnType<typeof peers>>,
  first: AuthMessage,
  certificates: VerifiableCertificate[]
): Promise<AuthMessage> {
  const initialNonce = Utils.toBase64(Array.from({ length: 48 }, () => 7))
  const { signature } = await f.holder.createSignature({
    data: [
      ...Utils.toArray(first.yourNonce ?? '', 'base64'),
      ...Utils.toArray(initialNonce, 'base64')
    ],
    protocolID: [2, 'auth message signature'],
    keyID: `${first.yourNonce ?? ''} ${initialNonce}`,
    counterparty: f.verifierIdentity
  })
  return { ...first, initialNonce, signature, certificates }
}

describe('Peer zero-field certificate exchange', () => {
  afterEach(() => jest.restoreAllMocks())

  it('authenticates a signed metadata-only core in a real initial response and sends a general message', async () => {
    const f = await peers()
    const handshake = f.verifierPeer.getAuthenticatedSession(f.holderIdentity)
    await f.holderTransport.deliver(await f.verifierTransport.next())
    const response = await f.holderTransport.next()
    expect(response.messageType).toBe('initialResponse')
    expect(response.certificates?.[0].keyring).toEqual({})
    await f.verifierTransport.deliver(response)
    await expect(handshake).resolves.toMatchObject({
      isAuthenticated: true,
      certificatesValidated: true,
      peerIdentityKey: f.holderIdentity
    })
    expect(f.proveCertificate).toHaveBeenCalledTimes(1)
    expect(f.proveCertificate).toHaveBeenCalledWith(
      {
        certificate: f.master,
        fieldsToReveal: [],
        verifier: f.verifierIdentity
      },
      undefined
    )
    expect(f.certificatesReceived).toHaveBeenCalledTimes(1)
    expect(f.decrypt).not.toHaveBeenCalled()
    const received = jest.fn()
    f.holderPeer.listenForGeneralMessages(received)
    await f.verifierPeer.toPeer([1, 2, 3], f.holderIdentity)
    await f.holderTransport.deliver(await f.verifierTransport.next())
    expect(received).toHaveBeenCalledWith(f.verifierIdentity, [1, 2, 3])
  })

  it('uses an independent snapshot when the configured request changes in flight', async () => {
    const f = await peers()
    const handshake = f.verifierPeer.getAuthenticatedSession(f.holderIdentity)
    const request = await f.verifierTransport.next()
    // The live, public configuration is mutated in flight. The constructor already
    // copied the caller's object, so mutating that copy's source would exercise nothing.
    f.verifierPeer.certificatesToRequest.certifiers.length = 0
    f.verifierPeer.certificatesToRequest.types[f.master.type].push('name')
    await f.holderTransport.deliver(request)
    await f.verifierTransport.deliver(await f.holderTransport.next())
    await expect(handshake).resolves.toMatchObject({ certificatesValidated: true })
    expect(f.certificatesReceived).toHaveBeenCalledTimes(1)
    expect(f.decrypt).not.toHaveBeenCalled()
  })

  it('keeps zero-field authority when the authenticated CAS winner persisted the same policy', async () => {
    const f = await peers([], 'cas-matching')
    const handshake = f.verifierPeer.getAuthenticatedSession(f.holderIdentity)
    await f.holderTransport.deliver(await f.verifierTransport.next())
    const response = await f.holderTransport.next()
    expect(response.certificates?.[0].keyring).toEqual({})

    await f.verifierTransport.deliver(response)

    await expect(handshake).resolves.toMatchObject({
      isAuthenticated: true,
      certificatesValidated: true,
      peerIdentityKey: f.holderIdentity
    })
    expect(f.certificatesReceived).toHaveBeenCalledTimes(1)
    expect(f.decrypt).not.toHaveBeenCalled()
  })

  it.each(['dropped', 'changed'] as const)(
    'revokes zero-field authority when the authenticated CAS winner has a %s policy',
    async policyState => {
      const f = await peers([], `cas-${policyState}`)
      void f.verifierPeer.getAuthenticatedSession(f.holderIdentity).catch(() => {})
      await f.holderTransport.deliver(await f.verifierTransport.next())
      const response = await f.holderTransport.next()
      expect(response.certificates?.[0].keyring).toEqual({})

      await expect(f.verifierTransport.deliver(response)).rejects.toThrow('A keyring is required')

      expect(f.certificatesReceived).not.toHaveBeenCalled()
      expect(f.decrypt).not.toHaveBeenCalled()
    }
  )

  it('does not let transport mutation alias the locally retained field request', async () => {
    const f = await peers(['name'])
    f.verifierTransport.rewrite = message => {
      if (message.messageType === 'initialRequest' && message.requestedCertificates !== undefined) {
        message.requestedCertificates.types[f.master.type].length = 0
      }
    }
    void f.verifierPeer.getAuthenticatedSession(f.holderIdentity).catch(() => {})
    await f.holderTransport.deliver(await f.verifierTransport.next())
    await expect(f.verifierTransport.deliver(await f.holderTransport.next())).rejects.toThrow(
      'A keyring is required'
    )
    expect(f.certificatesReceived).not.toHaveBeenCalled()
    expect(f.decrypt).not.toHaveBeenCalled()
  })

  it('validates the retained handshake snapshot, ignoring later custom serialization of the live configuration', async () => {
    const f = await peers()
    const toJSON = jest.fn(() => ({
      certifiers: [f.master.certifier],
      types: { [f.master.type]: ['name'] }
    }))
    const handshake = f.verifierPeer.getAuthenticatedSession(f.holderIdentity)
    const request = await f.verifierTransport.next()
    // Custom serialization added to the live configuration after the request left
    // must not reach validation: the retained handshake snapshot is what is validated.
    Reflect.set(f.verifierPeer.certificatesToRequest, 'toJSON', toJSON)
    expect(request.requestedCertificates).toEqual({
      certifiers: [f.master.certifier],
      types: { [f.master.type]: [] }
    })
    await f.holderTransport.deliver(request)
    await f.verifierTransport.deliver(await f.holderTransport.next())
    await expect(handshake).resolves.toMatchObject({ certificatesValidated: true })
    expect(toJSON).not.toHaveBeenCalled()
    expect(f.proveCertificate).toHaveBeenCalledWith(
      {
        certificate: f.master,
        fieldsToReveal: [],
        verifier: f.verifierIdentity
      },
      undefined
    )
    expect(f.decrypt).not.toHaveBeenCalled()
  })

  it('preserves the request snapshot through an asynchronous serialized session store', async () => {
    const f = await peers([], 'async')
    const handshake = f.verifierPeer.getAuthenticatedSession(f.holderIdentity)
    await f.holderTransport.deliver(await f.verifierTransport.next())
    await f.verifierTransport.deliver(await f.holderTransport.next())
    await expect(handshake).resolves.toMatchObject({
      certificatesValidated: true,
      certificatePolicy: f.requested
    })
    expect(f.certificatesReceived).toHaveBeenCalledTimes(1)
    expect(f.decrypt).not.toHaveBeenCalled()
  })

  it('refuses a same-type nonempty-to-empty downgrade despite mutated config and sender request', async () => {
    const f = await peers(['name'])
    void f.verifierPeer.getAuthenticatedSession(f.holderIdentity).catch(() => {})
    await f.holderTransport.deliver(await f.verifierTransport.next())
    const response = await f.holderTransport.next()
    f.verifierPeer.certificatesToRequest.types[f.master.type].length = 0
    response.requestedCertificates = f.verifierPeer.certificatesToRequest
    if (response.certificates === undefined) throw new Error('Expected a certificate')
    response.certificates[0].keyring = {}
    await expect(f.verifierTransport.deliver(response)).rejects.toThrow('A keyring is required')
    expect(f.certificatesReceived).not.toHaveBeenCalled()
    expect(f.decrypt).not.toHaveBeenCalled()
  })

  it('fails closed if an external session store loses the local request snapshot', async () => {
    const f = await peers()
    void f.verifierPeer.getAuthenticatedSession(f.holderIdentity).catch(() => {})
    await f.holderTransport.deliver(await f.verifierTransport.next())
    const response = await f.holderTransport.next()
    const session = f.verifierPeer.sessionManager.getSession(response.yourNonce ?? '')
    if (session === undefined) throw new Error('Expected a session')
    delete session.certificatePolicy
    await expect(f.verifierTransport.deliver(response)).rejects.toThrow('A keyring is required')
    expect(f.certificatesReceived).not.toHaveBeenCalled()
  })

  it.each([
    { mode: 'no certificates', required: false, fields: [] },
    { mode: 'nonempty disclosure', required: true, fields: ['name'] },
    { mode: 'zero-field disclosure', required: true, fields: [] }
  ])('preserves legacy serialized-store behavior for $mode', async ({ required, fields }) => {
    const f = await peers(fields, 'legacy', required)
    const handshake = f.verifierPeer.getAuthenticatedSession(f.holderIdentity)
    await f.holderTransport.deliver(await f.verifierTransport.next())
    const response = await f.holderTransport.next()
    if (required && fields.length === 0) {
      // The refused handshake only settles at the initial-response timeout.
      void handshake.catch(() => {})
      await expect(f.verifierTransport.deliver(response)).rejects.toThrow('A keyring is required')
      expect(f.certificatesReceived).not.toHaveBeenCalled()
      expect(f.decrypt).not.toHaveBeenCalled()
    } else {
      await f.verifierTransport.deliver(response)
      await expect(handshake).resolves.toMatchObject({
        isAuthenticated: true,
        certificatesValidated: true
      })
      expect(f.certificatesReceived).toHaveBeenCalledTimes(required ? 1 : 0)
      expect(f.decrypt).toHaveBeenCalledTimes(required ? 1 : 0)
    }
    expect(f.proveCertificate).toHaveBeenCalledTimes(required ? 1 : 0)
  })

  it.each(['nonce', 'signature'] as const)(
    'rejects an altered initial-response %s',
    async field => {
      const f = await peers()
      void f.verifierPeer.getAuthenticatedSession(f.holderIdentity).catch(() => {})
      await f.holderTransport.deliver(await f.verifierTransport.next())
      const response = await f.holderTransport.next()
      if (field === 'nonce')
        response.yourNonce = Utils.toBase64(Array.from({ length: 32 }, () => 0))
      if (field === 'signature') response.signature = [1, 2, 3]
      await expect(f.verifierTransport.deliver(response)).rejects.toThrow()
      expect(f.certificatesReceived).not.toHaveBeenCalled()
      expect(f.decrypt).not.toHaveBeenCalled()
    }
  )

  it('rejects a correctly signed response relabeled to another holder identity', async () => {
    const f = await peers()
    void f.verifierPeer.getAuthenticatedSession(f.holderIdentity).catch(() => {})
    const request = await f.verifierTransport.next()
    await f.holderTransport.deliver(request)
    const response = await f.holderTransport.next()
    const other = new CompletedProtoWallet(new PrivateKey(84))
    const identity = (await other.getPublicKey({ identityKey: true })).publicKey
    const master = await MasterCertificate.issueCertificateForSubject(
      f.issuer,
      identity,
      { name: 'Other synthetic holder' },
      f.master.type,
      async () => `${'56'.repeat(32)}.0`
    )
    response.identityKey = identity
    if (master.signature === undefined) throw new Error('Expected an issuer-signed fixture')
    response.certificates = [
      VerifiableCertificate.fromCertificate({ ...master, signature: master.signature }, {})
    ]
    const { signature } = await other.createSignature({
      data: [
        ...Utils.toArray(response.yourNonce ?? '', 'base64'),
        ...Utils.toArray(response.initialNonce ?? '', 'base64')
      ],
      protocolID: [2, 'auth message signature'],
      keyID: `${response.yourNonce ?? ''} ${response.initialNonce ?? ''}`,
      counterparty: f.verifierIdentity
    })
    response.signature = signature
    await expect(f.verifierTransport.deliver(response)).rejects.toThrow(
      'does not match the requested peer identity'
    )
    expect(f.certificatesReceived).not.toHaveBeenCalled()
    expect(f.decrypt).not.toHaveBeenCalled()
  })

  it.each([false, true])(
    'refuses a standalone zero-field response, including sender authority=%s',
    async senderAuthority => {
      const f = await peers()
      const handshake = f.verifierPeer.getAuthenticatedSession(f.holderIdentity)
      await f.holderTransport.deliver(await f.verifierTransport.next())
      await f.verifierTransport.deliver(await f.holderTransport.next())
      await handshake
      f.certificatesReceived.mockClear()
      // A new nonempty request cannot be downgraded by the holder's unsigned
      // requestedCertificates member on a separately signed certificateResponse.
      // The holder handles the signed request itself, which authenticates the
      // responder-side session, so the standalone response under test is exactly
      // the zero-field proof rather than an automatic nonempty disclosure.
      f.holderPeer.listenForCertificatesRequested(jest.fn())
      await f.verifierPeer.requestCertificates(
        {
          certifiers: [f.master.certifier],
          types: { [f.master.type]: ['name'] }
        },
        f.holderIdentity
      )
      await f.holderTransport.deliver(await f.verifierTransport.next())
      await f.holderPeer.sendCertificateResponse(f.verifierIdentity, [
        VerifiableCertificate.fromCertificate(f.master, {})
      ])
      const response = await f.holderTransport.next()
      if (senderAuthority) response.requestedCertificates = f.requested
      await expect(f.verifierTransport.deliver(response)).rejects.toThrow(
        'do not match a locally requested set'
      )
      // Replaying the same standalone response is refused as a consumed nonce and
      // cannot reach any acceptance path.
      await expect(f.verifierTransport.deliver(response)).rejects.toThrow(
        'Replayed certificateResponse'
      )
      expect(f.certificatesReceived).not.toHaveBeenCalled()
      expect(f.decrypt).not.toHaveBeenCalled()
    }
  )

  it('preserves the existing nonempty standalone certificate response path', async () => {
    const f = await peers()
    const handshake = f.verifierPeer.getAuthenticatedSession(f.holderIdentity)
    await f.holderTransport.deliver(await f.verifierTransport.next())
    await f.verifierTransport.deliver(await f.holderTransport.next())
    await handshake
    f.certificatesReceived.mockClear()
    await f.verifierPeer.requestCertificates(
      {
        certifiers: [f.master.certifier],
        types: { [f.master.type]: ['name'] }
      },
      f.holderIdentity
    )
    await f.holderTransport.deliver(await f.verifierTransport.next())
    await f.verifierTransport.deliver(await f.holderTransport.next())
    expect(f.certificatesReceived).toHaveBeenCalledTimes(1)
    expect(f.decrypt).toHaveBeenCalledTimes(1)
  })

  it('in-flight mutation of the live peer.certificatesToRequest does not change the handshake snapshot', async () => {
    const f = await peers()
    const handshake = f.verifierPeer.getAuthenticatedSession(f.holderIdentity)
    const request = await f.verifierTransport.next()
    f.verifierPeer.certificatesToRequest.certifiers.length = 0
    f.verifierPeer.certificatesToRequest.types[f.master.type].push('name')
    await f.holderTransport.deliver(request)
    await f.verifierTransport.deliver(await f.holderTransport.next())
    await expect(handshake).resolves.toMatchObject({ certificatesValidated: true })
    expect(f.decrypt).not.toHaveBeenCalled()
  })

  it('live config downgraded to fields=[] after a nonempty request cannot accept a zero-field proof', async () => {
    const f = await peers(['name'])
    void f.verifierPeer.getAuthenticatedSession(f.holderIdentity).catch(() => {})
    await f.holderTransport.deliver(await f.verifierTransport.next())
    const response = await f.holderTransport.next()
    f.verifierPeer.certificatesToRequest.types[f.master.type].length = 0
    if (response.certificates === undefined) throw new Error('Expected a certificate')
    response.certificates[0].keyring = {}
    await expect(f.verifierTransport.deliver(response)).rejects.toThrow('A keyring is required')
    expect(f.certificatesReceived).not.toHaveBeenCalled()
  })

  it('a refilled default never becomes zero-field authority on a later initialResponse', async () => {
    const f = await peers(['name'])
    void f.verifierPeer.getAuthenticatedSession(f.holderIdentity).catch(() => {})
    await f.holderTransport.deliver(await f.verifierTransport.next())
    const response = await f.holderTransport.next()
    // The app reconfigures the public default for future peers; the store loses the snapshot once.
    f.verifierPeer.certificatesToRequest = {
      certifiers: [f.master.certifier],
      types: { [f.master.type]: [] }
    }
    const session = f.verifierPeer.sessionManager.getSession(response.yourNonce ?? '')
    if (session === undefined) throw new Error('Expected a session')
    delete session.certificatePolicy
    const zero: VerifiableCertificate = JSON.parse(
      JSON.stringify(VerifiableCertificate.fromCertificate(f.master, {}))
    )
    await expect(
      f.verifierTransport.deliver({ ...response, certificates: [zero] })
    ).rejects.toThrow('A keyring is required')
    // As upstream, the configured default refills the lost snapshot; that is not authority.
    expect(
      f.verifierPeer.sessionManager.getSession(response.yourNonce ?? '')?.certificatePolicy
    ).toEqual({ certifiers: [f.master.certifier], types: { [f.master.type]: [] } })
    const second = await secondInitialResponse(f, response, [zero])
    await expect(f.verifierTransport.deliver(second)).rejects.toThrow('A keyring is required')
    expect(f.verifierPeer.sessionManager.getSession(response.yourNonce ?? '')).toMatchObject({
      isAuthenticated: true,
      peerNonce: response.initialNonce,
      certificatesValidated: false
    })
    expect(f.certificatesReceived).not.toHaveBeenCalled()
    expect(f.decrypt).not.toHaveBeenCalled()
  })

  it('a lost snapshot fails closed on every initialResponse, not only the first', async () => {
    const f = await peers()
    void f.verifierPeer.getAuthenticatedSession(f.holderIdentity).catch(() => {})
    await f.holderTransport.deliver(await f.verifierTransport.next())
    const response = await f.holderTransport.next()
    const session = f.verifierPeer.sessionManager.getSession(response.yourNonce ?? '')
    if (session === undefined) throw new Error('Expected a session')
    delete session.certificatePolicy
    await expect(f.verifierTransport.deliver(response)).rejects.toThrow('A keyring is required')
    const second = await secondInitialResponse(
      f,
      response,
      response.certificates as VerifiableCertificate[]
    )
    await expect(f.verifierTransport.deliver(second)).rejects.toThrow('A keyring is required')
    expect(f.certificatesReceived).not.toHaveBeenCalled()
    expect(f.decrypt).not.toHaveBeenCalled()
  })

  it('a responder-created session grants no zero-field authority to a reflected initialResponse', async () => {
    const f = await peers()
    // The holder initiates, so the verifier's session with its policy is responder-created.
    void f.holderPeer.getAuthenticatedSession(f.verifierIdentity).catch(() => {})
    await f.verifierTransport.deliver(await f.holderTransport.next())
    const verifierResponse = await f.verifierTransport.next()
    expect(verifierResponse.messageType).toBe('initialResponse')
    const responderNonce = verifierResponse.initialNonce ?? ''
    expect(f.verifierPeer.sessionManager.getSession(responderNonce)?.certificatePolicy).toEqual(
      f.requested
    )
    const initialNonce = Utils.toBase64(Array.from({ length: 48 }, () => 9))
    const { signature } = await f.holder.createSignature({
      data: [...Utils.toArray(responderNonce, 'base64'), ...Utils.toArray(initialNonce, 'base64')],
      protocolID: [2, 'auth message signature'],
      keyID: `${responderNonce} ${initialNonce}`,
      counterparty: f.verifierIdentity
    })
    const zero: VerifiableCertificate = JSON.parse(
      JSON.stringify(VerifiableCertificate.fromCertificate(f.master, {}))
    )
    await expect(
      f.verifierTransport.deliver({
        version: '0.1',
        messageType: 'initialResponse',
        identityKey: f.holderIdentity,
        initialNonce,
        yourNonce: responderNonce,
        certificates: [zero],
        signature
      })
    ).rejects.toThrow('A keyring is required')
    expect(f.verifierPeer.sessionManager.getSession(responderNonce)?.certificatesValidated).toBe(
      false
    )
    expect(f.certificatesReceived).not.toHaveBeenCalled()
    expect(f.decrypt).not.toHaveBeenCalled()
  })

  it('a Peer restarted over an external store has no zero-field authority', async () => {
    const f = await peers([], 'async')
    void f.verifierPeer.getAuthenticatedSession(f.holderIdentity).catch(() => {})
    await f.holderTransport.deliver(await f.verifierTransport.next())
    const response = await f.holderTransport.next()
    // Same wallet and store, new instance: the store kept the snapshot, the memory did not.
    const store = f.verifierPeer.sessionManager as unknown as AsyncSessionManager
    expect((await store.getSession(response.yourNonce ?? ''))?.certificatePolicy).toEqual(
      f.requested
    )
    const restartedTransport = new QueuedTransport()
    const restarted = new Peer(f.verifier, restartedTransport, f.requested, store)
    await restarted.ready
    const received = jest.fn()
    restarted.listenForCertificatesReceived(received)
    await expect(restartedTransport.deliver(response)).rejects.toThrow('A keyring is required')
    expect(received).not.toHaveBeenCalled()
    expect(f.decrypt).not.toHaveBeenCalled()
  })

  it('a handshake that fails releases its zero-field authority', async () => {
    const f = await peers()
    let request: AuthMessage | undefined
    f.verifierTransport.send = async message => {
      request = JSON.parse(JSON.stringify(message))
      throw new Error('transport down')
    }
    await expect(f.verifierPeer.getAuthenticatedSession(f.holderIdentity)).rejects.toThrow(
      'transport down'
    )
    if (request === undefined) throw new Error('Expected the initial request')
    const sessionNonce = request.initialNonce ?? ''
    expect(f.verifierPeer.sessionManager.getSession(sessionNonce)).toBeUndefined()
    // A store that kept the session anyway, and a late response to it, still grant nothing.
    f.verifierPeer.sessionManager.addSession({
      isAuthenticated: false,
      sessionNonce,
      peerIdentityKey: f.holderIdentity,
      lastUpdate: Date.now(),
      certificatePolicy: f.requested,
      certificatesRequired: true,
      certificatesValidated: false
    })
    await f.holderTransport.deliver(request)
    await expect(f.verifierTransport.deliver(await f.holderTransport.next())).rejects.toThrow(
      'A keyring is required'
    )
    expect(f.certificatesReceived).not.toHaveBeenCalled()
    expect(f.decrypt).not.toHaveBeenCalled()
  })
})
