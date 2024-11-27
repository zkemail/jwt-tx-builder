pragma circom 2.1.6;

include "../../examples/jwt-auth-with-anon-domains.circom";

component main { public [ anonymousDomainsTreeRoot ] } = JWTAuthWithAnonymousDomains(121, 17, 1024, 128, 896, 72, 605, 2);
