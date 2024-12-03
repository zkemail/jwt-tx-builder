/** RSA public key interface */
export interface RSAPublicKey {
  /** Base64-encoded modulus */
  n: string;
  /** Public exponent */
  e: number;
}

export interface JWTComponents {
  rawJWT: string;
  publicKey: RSAPublicKey;
}
