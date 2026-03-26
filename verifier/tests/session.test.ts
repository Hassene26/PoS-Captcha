import { sessionStore, issueToken, verifyToken } from '../src/session';

describe('Verifier Session Store & JWT', () => {
  
  beforeEach(() => {
    // Clear the store before each test
    (sessionStore as any).sessions.clear();
    (sessionStore as any).commitments.clear();
  });

  test('should create a new session correctly', () => {
    const seed = 42;
    const session = sessionStore.create(seed);
    
    expect(session.sessionId).toBeDefined();
    expect(session.seed).toBe(seed);
    expect(session.status).toBe('pending_commitment');
    expect(sessionStore.size()).toBe(1);
  });

  test('should register and retrieve a commitment', () => {
    const clientId = 'test-client-123';
    const mockCommitment = {
      rootHashes: ['hash1', 'hash2'],
      numBlockGroups: 2,
      registeredAt: Date.now(),
      clientId
    };

    sessionStore.registerCommitment(clientId, mockCommitment);
    
    const retrieved = sessionStore.getCommitment(clientId);
    expect(retrieved).toBeDefined();
    expect(retrieved?.numBlockGroups).toBe(2);
    expect(retrieved?.rootHashes.length).toBe(2);
  });

  test('should update a session status', () => {
    const session = sessionStore.create(99);
    
    sessionStore.update(session.sessionId, { status: 'passed' });
    
    const updated = sessionStore.get(session.sessionId);
    expect(updated?.status).toBe('passed');
  });

  test('should issue and verify a JWT token', () => {
    const sessionId = 'session-xyz';
    const clientId = 'client-xyz';
    
    // Issue token
    const token = issueToken(sessionId, clientId);
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(20);

    // Verify token
    const decoded = verifyToken(token);
    expect(decoded).not.toBeNull();
    expect(decoded.sessionId).toBe(sessionId);
    expect(decoded.clientId).toBe(clientId);
    expect(decoded.verified).toBe(true);
  });

  test('should return null for invalid token', () => {
    const decoded = verifyToken('invalid.token.string');
    expect(decoded).toBeNull();
  });
});
