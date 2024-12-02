pragma circom 2.1.6;

include "../../jwt-auth.circom";

component main = JWTAuth(121, 17, 1024, 128, 896, 72, 605);
