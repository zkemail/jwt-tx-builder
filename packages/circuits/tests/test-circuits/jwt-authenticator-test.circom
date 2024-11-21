pragma circom 2.1.6;

include "../../jwt-authenticator-template.circom";

component main = JWTAuthenticator(121, 17, 1024, 128, 896, 72, 605);
