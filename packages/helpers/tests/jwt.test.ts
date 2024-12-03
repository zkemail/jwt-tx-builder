import { generateJWT, verifyJWT } from '../src/jwt';
import { RSAPublicKey } from '../src/types';

describe('verifyJWT', () => {
  let rawJWT: string;
  let publicKey: RSAPublicKey;

  beforeAll(async () => {
    const header = {
      alg: 'RS256',
      typ: 'JWT',
    };
    const payload = {
      sub: '1234567890',
      name: 'John Doe',
      iat: Math.floor(Date.now() / 1000),
    };

    const { rawJWT: jwt, publicKey: key } = generateJWT(header, payload);
    rawJWT = jwt;
    publicKey = key;
  });

  it('should verify a valid JWT', async () => {
    const isVerified = await verifyJWT(rawJWT, publicKey);
    expect(isVerified).toBe(true);
  });

  it('should throw an error for an invalid JWT', async () => {
    await expect(verifyJWT('', publicKey)).rejects.toThrow('Invalid JWT: JWT token must be provided.');
  });

  it('should throw an error for an invalid signature', async () => {
    const invalidJWT = `${rawJWT.split('.')[0]}.${rawJWT.split('.')[1]}.invalidSignature`;
    expect(await verifyJWT(invalidJWT, publicKey)).toBe(false);
  });
});
