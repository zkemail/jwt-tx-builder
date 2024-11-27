pragma circom 2.1.6;

include "../../jwt-verifier.circom";

component main = JWTVerifier(121, 17, 1024, 128, 896);
