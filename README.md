# OpenID Connect for Verifiable Credential presentation

## Abstract

This specification defines additional parameters `vp_jwt`, `vp_ldp`, `vc_jwt`, `vc_ldp`. The new parameter allows OpenID Connect OPs to provide RPs with End-User claims as W3C Verifiable Presentations or W3C Verifiable Credentials in the `id_token` or via Userinfo responses.

## Authors

- Oliver Terbu (ConsenSys Mesh)
- Torsten Lodderstedt (yes.com)
- Kristina Yasuda (Microsoft)
- Adam Lemmon (Trybe.ID)
- Tobias Looker (Mattr)

## Terminology

Credential

A set of one or more claims made by an issuer. (see https://www.w3.org/TR/vc-data-model/#terminology)

Verifiable Credential

A verifiable credential is a tamper-evident credential that has authorship that can be cryptographically verified. Verifiable credentials can be used to build verifiable presentations, which can also be cryptographically verified. The claims in a credential can be about different subjects. (see https://www.w3.org/TR/vc-data-model/#terminology)

Presentation

Data derived from one or more verifiable credentials, issued by one or more issuers, that is shared with a specific verifier. (see https://www.w3.org/TR/vc-data-model/#terminology)

Verified Presentation

A verifiable presentation is a tamper-evident presentation encoded in such a way that authorship of the data can be trusted after a process of cryptographic verification. Certain types of verifiable presentations might contain data that is synthesized from, but do not contain, the original verifiable credentials (for example, zero-knowledge proofs). (see https://www.w3.org/TR/vc-data-model/#terminology)

## Introduction

This specification extends OpenID Connect with support for presentation of claims via W3C Verifiable Credentials. This allows existing OpenID Connect RPs to extends their reach towards claims sources asserting claims in this format. It also allows new applications built using Verifiable Credentials to utilize OpenID Connect as integration and interoperability layer towards credential holders. 

This specification supports two ways to present Verifiable Credentials. Its is possible to provide the RP directly with a Verificable Credential or to use a Verifiable Presentation.

The Verifiable Credential (VC) can be used to assert claims towards a Verifier under some circumstances. Either the credential is a bearer credential, i.e. it is not bound to a certain secret that requires proof of control when presenting the credential, or the link between the subject of the credential and the presenter of the credential can be established by other means, e.g. by proofing control over the subject's DID in the same process. 

Verifiable Presentations (VP) are used to present claims along with cryptographic proofs of the link between presenter and subject of the verifiable credentials it contains. A verifiable presentation can contain a subset of claims asserted in a certain credential (selective disclosure) and it can assemble claims from different credentials. 

There are two formats of VCs and VPs: JWT and JSON-LD. Each of those formats has different properties and capabilites and each of them comes with different proof types. The JWT format can be used with JSON Web Signatures (https://www.w3.org/TR/vc-data-model/#json-web-token). JSON-LD is used with different kinds of Linked Data Proofs and JSON Web Signatures (https://www.w3.org/TR/vc-data-model/#json-ld).

This specification defines standard claims that allow implementations to use any of the four representations of Verifiable Credential objects (vp_jwt, vp_ldp, vc_jwt, vc_ldp) with JWTs (such as ID tokens) and sets of JSON claims (such as UserInfo Endpoint responses). 

This specification supports all beforementioned assertion and proof formats. 

## Use Cases

### Verifier accesses Wallet via OpenID Connect

A Verifier uses OpenID Connect to obtain verifiable presentations. This is a simple and mature way to obtain identity data. From a technical perspective, this also makes integration with OAuth-protected APIs easier as OpenID Connect is based on OAuth.  

### Existing OpenID Connect RP integrates SSI wallets

An application currently utilizing OpenID Connect for accessing various federated identity providers can use the same protocol to also integrate with emerging SSI-based wallets. Thats an conveient transition path leveraging existing expertise and protecting investments made.

### Existing OpenID Connect OP as custodian of End-User Credentials

An existing OpenID Connect may extends its service by maintaining credentials issued by other claims sources on behalf of its customers. Customers can mix claims of the OP and from their credentials to fulfil authentication requests. 

### Federated OpenID Connect OP adds device-local mode

An extisting OpenID Connect OP with a native user experience (PWA or native app) issues Verifiable Credentials and stores it on the user's device linked to a private key residing on this device under the user's control. For every authentication request, the native user experience first checks whether this request can be fulfilled using the locally stored credentials. If so, it generates a presentations signed with the user's keys in order to prevent replay of the credential. 

This approach dramatically reduces latency and reduces load on the OP's servers. Moreover, the user can identity, authenticate, and authorize even in situations with unstable or without internet connectivity. 

## Overview
This specifications introduces the following mechanisms to provide VCs and VPs to RPs:
* In the ID Token: An ID Token may contain a claim `vp_jwt`, `vp_ldp`, `vc_jwt`, or `vc_ldp`.
* From the UserInfo Response: UserInfo response may contain a claim `vp_jwt`, `vp_ldp`, `vc_jwt`, or `vc_ldp`.

Note that OP would first encode VPs/VCs using the rules defined in the Verifiable Credential specification either in JWT format or JSON-LD format, before passing encoded VPs/VCs as `vp_jwt`, `vp_ldp`, `vc_jwt`, or `vc_ldp` parameters as JWT claims or as sets of JSON claims.


# JWT Claims to represent W3C Verifiable Credentials objects

W3C Verifiable Credentials specification defines two kinds of objects – Verifiable Credentials and Verifiable Presentations, and it also orthogonally defines two proof formats of these objects – JWT and Linked Data Proofs. Thus, there are four data types that different use cases could utilize.
 
This specification defines the following parameters to pass Verifiable Presentations or Verifiable Credentials signed as JWTs or using Linked Data Proofs:

- vc_jwt:  A claim whose value is a W3C Verifiable Credential object using the JWT representation, which is a JSON string.  The claim’s value may also be an array of W3C Verifiable Credential objects using the JWT representation if the use case calls for multiple JWT VCs.

- vp_jwt:  A claim whose value is a W3C Verifiable Presentation object using the JWT representation, which is a JSON string.  The claim’s value may also be an array of W3C Verifiable Presentation objects using the JWT representation if the use case calls for multiple JWT VPs.

- vc_ldp:  A claim whose value is a W3C Verifiable Credential object using the JSON-LD representation, which is a JSON object.  The claim’s value may also be an array of W3C Verifiable Credential objects using the JSON-LD representation if the use case calls for multiple JSON-LD VCs.

- vp_ldp:  A claim whose value is a W3C Verifiable Presentation object using the JSON-LD representation, which is a JSON object.  The claim’s value may also be an array of W3C Verifiable Presentation objects using the JSON-LD representation if the use case calls for multiple JSON-LD VPs.

# W3C Verifiable Credentials objects returned with JWTs 
This section illustrates the response when W3C Verifiable Credentials objects are returned with JTWs such as inside ID Token.

## Self-Issued OP Response
Below are the examples when W3C Verifiable Credentials are returned inside ID Token as part of Self-Issued OP response. ID Token contains a `vp_jwt` or `vp_ldp` element with the Verifiable Presentation data, or a `vc_jwt` or `vc_ldp` element with the Verifiable Credential data. 

### ID Token with Verifiable Credentials signed as JWTs

Below is a non-normative example of ID Token that includes `vp_jwt` claim.

```
{
  "kid": "did:ion:EiC6Y9_aDaCsITlY06HId4seJjJ...b1df31ec42d0",
  "typ": "JWT",
  "alg": "ES256K"
}.{
   "iss":"https://book.itsourweb.org:3000/wallet/wallet.html",
   "aud":"https://book.itsourweb.org:3000/client_api/authresp/uhn",
   "iat":1615910538,
   "exp":1615911138,
   "sub":""did:ion:EiC6Y9_aDaCsITlY06HId4seJjJ-9...mS3NBIn19",
   "auth_time":1615910535,
   "nonce":"960848874",
   "vp_jwt":[
            "ewogICAgImlzcyI6Imh0dHBzOi8vYm9vay5pdHNvdXJ3ZWIub...IH0="
   ],   
   "sub_jwk":{
      "crv":"P-384",
      "kty":"EC",
      "kid": "c7298a61a6904426a580b1df31ec42d0",
      "x":"jf3a6dquclZ4PJ0JMU8RuucG9T1O3hpU_S_79sHQi7VZBD9e2VKXPts9lUjaytBm",
      "y":"38VlVE3kNiMEjklFe4Wo4DqdTKkFbK6QrmZf77lCMN2x9bENZoGF2EYFiBsOsnq0"
   }
}
```

Below is a non-normative example of a decoded Verifiable Presentation object that was included in `vp_jwt`. 
Note that `vp` is used to contain only "those parts of the standard verifiable presentation where no explicit encoding rules for JWT exist" [VC-DATA-MODEL]

```
  {
    "iss":"urn:uuid:68f874e2-377c-437f-a447-b304967ca351",
    "jti":"urn:uuid:68f874e2-377c-437f-a447-b304967ca351",
    "aud":"https://book.itsourweb.org:3000/ohip",
    "iat":1615910538,
    "exp":1615911138,   
    "nbf":1615910538,
    "nonce":"acIlfiR6AKqGHg",
    "vp":{
        "@context":[
          "https://www.w3.org/2018/credentials/v1",
          "https://ohip.ontario.ca/v1"
        ],
        "type":[
          "VerifiablePresentation"
        ],
        "verifiableCredential":[
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InVybjp1dWlkOjU0ZDk2NjE2LTE1MWUt...OLryT1g"    
        ]
    }   
  }
```

### ID Token with Verifiable Presentation signed using Linked Data Format

Below is a non-normative example of ID Token that includes `vp_ldp` claim.

```
{
   "iss":"https://book.itsourweb.org:3000/wallet/wallet.html",
   "aud":"https://book.itsourweb.org:3000/client_api/authresp/uhn",
   "iat":1615910538,
   "exp":1615911138,
   "sub":"urn:uuid:68f874e2-377c-437f-a447-b304967ca351",
   "auth_time":1615910535,
   "vp_ldp":[
     {
      "@context":[
         "https://www.w3.org/2018/credentials/v1"
      ],
      "type":[
         "VerifiablePresentation"
      ],
      "verifiableCredential":[
         {
            "@context":[
               "https://www.w3.org/2018/credentials/v1",
               "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id":"https://example.com/credentials/1872",
            "type":[
               "VerifiableCredential",
               "IDCardCredential"
            ],
            "issuer":{
               "id":"did:example:issuer"
            },
            "issuanceDate":"2010-01-01T19:23:24Z",
            "credentialSubject":{
               "given_name":"Fredrik",
               "family_name":"Strömberg",
               "birthdate":"1949-01-22"
            },
            "proof":{
               "type":"Ed25519Signature2018",
               "created":"2021-03-19T15:30:15Z",
               "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PT8yCqVjj5ZHD0W36zsBQ47oc3El07WGPWaLUuBTOT48IgKI5HDoiFUt9idChT_Zh5s8cF_2cSRWELuD8JQdBw",
               "proofPurpose":"assertionMethod",
               "verificationMethod":"did:example:issuer#keys-1"
            }
         }
      ],
      "id":"ebc6f1c2",
      "holder":"did:example:holder",
      "proof":{
         "type":"Ed25519Signature2018",
         "created":"2021-03-19T15:30:15Z",
         "challenge":"()&)()0__sdf",
         "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..GF5Z6TamgNE8QjE3RbiDOj3n_t25_1K7NVWMUASe_OEzQV63GaKdu235MCS3hIYvepcNdQ_ZOKpGNCf0vIAoDA",
         "proofPurpose":"authentication",
         "verificationMethod":"did:example:holder#key-1"
       }
     }
   ],
   "nonce":"960848874",
   "sub_jwk":{
      "crv":"P-384",
      "kty":"EC",
      "x":"jf3a6dquclZ4PJ0JMU8RuucG9T1O3hpU_S_79sHQi7VZBD9e2VKXPts9lUjaytBm",
      "y":"38VlVE3kNiMEjklFe4Wo4DqdTKkFbK6QrmZf77lCMN2x9bENZoGF2EYFiBsOsnq0"
   }
}
```


# W3C Verifiable Credentials objects returned as sets of JSON claims (backchannel)
This section illustrates the response when W3C Verifiable Credentials objects are returned as sets of JSON claims such as user_info endpoint responses.

## UserInfo Response
Below are the examples when W3C Verifiable Credentials are returned from user_info endpoint utilizing the authorization code flow.

### UserInfo Response with with Verifiable Credentials signed as JWTs

Below is a non-normative example of a UserInfo Response that includes `vp_jwt` claim:

```
  HTTP/1.1 200 OK
  Content-Type: application/json

  {
   "sub": "248289761001",
   "name": "Jane Doe",
   "given_name": "Jane",
   "family_name": "Doe",
   "vp_jwt":["ewogICAgImlzcyI6Imh0dHBzOi8vYm9vay5pdHNvdXJ3ZWIub...IH0="]
  }
```

### UserInfo Response with with Verifiable Credentials signed using Linked Data Format

Below is a non-normative example of a UserInfo Response that includes `vp_ldp` claim:

```
  HTTP/1.1 200 OK
  Content-Type: application/json

  {
   "sub": "248289761001",
   "name": "Jane Doe",
   "given_name": "Jane",
   "family_name": "Doe",
   "vp_ldp":[
    {
      "@context":[
         "https://www.w3.org/2018/credentials/v1"
      ],
      "type":[
         "VerifiablePresentation"
      ],
      "verifiableCredential":[
         {
            "@context":[
               "https://www.w3.org/2018/credentials/v1",
               "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id":"https://example.com/credentials/1872",
            "type":[
               "VerifiableCredential",
               "IDCardCredential"
            ],
            "issuer":{
               "id":"did:example:issuer"
            },
            "issuanceDate":"2010-01-01T19:23:24Z",
            "credentialSubject":{
               "given_name":"Fredrik",
               "family_name":"Strömberg",
               "birthdate":"1949-01-22"
            },
            "proof":{
               "type":"Ed25519Signature2018",
               "created":"2021-03-19T15:30:15Z",
               "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PT8yCqVjj5ZHD0W36zsBQ47oc3El07WGPWaLUuBTOT48IgKI5HDoiFUt9idChT_Zh5s8cF_2cSRWELuD8JQdBw",
               "proofPurpose":"assertionMethod",
               "verificationMethod":"did:example:issuer#keys-1"
            }
         }
      ],
      "id":"ebc6f1c2",
      "holder":"did:example:holder",
      "proof":{
         "type":"Ed25519Signature2018",
         "created":"2021-03-19T15:30:15Z",
         "challenge":"()&)()0__sdf",
         "jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..GF5Z6TamgNE8QjE3RbiDOj3n_t25_1K7NVWMUASe_OEzQV63GaKdu235MCS3hIYvepcNdQ_ZOKpGNCf0vIAoDA",
         "proofPurpose":"authentication",
         "verificationMethod":"did:example:holder#key-1"
      }
    ]
  }
```


### Related Issues
- https://bitbucket.org/openid/connect/issues/1206/how-to-support-ld-proofs-in-verifiable#comment-60051830
