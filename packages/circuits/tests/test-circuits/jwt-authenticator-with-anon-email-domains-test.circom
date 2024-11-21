pragma circom 2.1.6;

include "../../jwt-authenticator-with-anon-domain-template.circom";

component main { public [ anonymousDomainsTreeRoot ] } = JWTAuthenticatorWithAnonymousDomain(121, 17, 1024, 128, 896, 72, 605, 2);
