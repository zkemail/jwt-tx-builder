import NodeRSA from 'node-rsa';
import { splitJWT } from './utils';
import { JWTComponents, RSAPublicKey } from './types';

/**
 * @description Generates a JSON Web Token (JWT) with the provided header and payload
 * @param header An object containing the JWT header information
 * @param payload An object containing the JWT payload information
 * @returns {JWTComponents} An object containing the raw JWT string and the public key components
 *
 * @example
 * const header = { alg: 'RS256', typ: 'JWT' };
 * const payload = { sub: '1234567890', name: 'John Doe', iat: 1516239022 };
 * const { rawJWT, publicKey } = generateJWT(header, payload);
 */
// TODO: Add options to generate JWT with custom key pair or options for different signing algorithms
export function generateJWT(header: object, payload: object): JWTComponents {
  const key = new NodeRSA();
  key.generateKeyPair(2048, 65537);

  const headerString = Buffer.from(JSON.stringify(header)).toString('base64');
  const payloadString = Buffer.from(JSON.stringify(payload)).toString('base64');

  const signature = key.sign(Buffer.from(`${headerString}.${payloadString}`), 'base64', 'utf8');

  const rawJWT = `${headerString}.${payloadString}.${signature}`;
  const publicKey = {
    n: key.exportKey('components').n.toString('base64'),
    e: key.exportKey('components').e,
  };

  return {
    rawJWT,
    publicKey: {
      ...publicKey,
      e: typeof publicKey.e === 'number' ? publicKey.e : parseInt(publicKey.e.toString('hex'), 16),
    },
  };
}

/**
 * @description Verify the JWT token using the provided RSA public key components
 * @param token The JWT token as a string
 * @param pubkey An object containing the modulus (n) and exponent (e) of the RSA public key
 * @returns A promise that resolves to a boolean indicating the verification result
 * @throws Error if the verification fails or if the token is malformed
 */
export async function verifyJWT(token: string, pubkey: RSAPublicKey): Promise<boolean> {
  if (!token) {
    throw new Error('Invalid JWT: JWT token must be provided.');
  }

  const [headerString, payloadString, signatureString] = splitJWT(token);

  const key = new NodeRSA();
  key.importKey(
    {
      n: Buffer.from(pubkey.n, 'base64'),
      e: pubkey.e,
    },
    'components-public',
  );

  const dataToVerify = `${headerString}.${payloadString}`;

  try {
    const isValidSignature = key.verify(Buffer.from(dataToVerify), signatureString, 'utf8', 'base64');

    return isValidSignature;
  } catch (error) {
    console.error('JWT verification error:', error);
    return false;
  }
}
