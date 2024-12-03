import { splitJWT, base64ToBigInt } from '../src/utils';

describe('Utility Functions', () => {
  describe('splitJWT', () => {
    it('should split a valid JWT into its components', () => {
      const jwt = 'header.payload.signature';
      const [header, payload, signature] = splitJWT(jwt);
      expect(header).toBe('header');
      expect(payload).toBe('payload');
      expect(signature).toBe('signature');
    });

    it('should throw an error for an invalid JWT format', () => {
      const invalidJWT = 'invalidJWT';
      expect(() => splitJWT(invalidJWT)).toThrow('Invalid JWT format: Missing components');
    });
  });

  describe('base64ToBigInt', () => {
    it('should convert a Base64 string to a bigint', () => {
      const encoded = 'AQAB';
      const decoded = base64ToBigInt(encoded);
      expect(decoded).toBe(65537n);
    });
  });
});
