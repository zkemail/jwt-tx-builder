import { Buffer } from 'buffer';

/**
 * @description Split a JWT token into its header, payload, and signature components
 * @param jwt The JWT token as a string
 * @returns An array containing the header, payload, and signature as base64 encoded strings
 */
export function splitJWT(jwt: string): [string, string, string] {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format: Missing components');
  }
  return [parts[0], parts[1], parts[2]];
}

/**
 * @description Converts a Base64 string to a bigint.
 * @param base64String The Base64-encoded string to convert.
 * @returns The corresponding bigint representation of the Base64 string.
 */
export function base64ToBigInt(base64String: string): bigint {
  return BigInt(`0x${Buffer.from(base64String, 'base64').toString('hex')}`);
}

/**
 * Converts a 32-byte (256-bit) bigint to a 64-character hex string with leading zeros.
 * @param bigInt A 256-bit bigint to convert
 * @returns A 64-character hex string
 * @throws Error if the input is not a 256-bit bigint
 */
export function bigInt256ToHex64(bigInt: bigint): string {
  // Check if the bigint is within the valid range for 256 bits
  if (bigInt < 0n || bigInt >= 1n << 256n) {
    throw new Error('Input must be a 256-bit bigint (32 bytes)');
  }

  const hexString = bigInt.toString(16);
  // Pad to 64 characters (32 bytes)
  return hexString.padStart(64, '0');
}
