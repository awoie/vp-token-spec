# OpenID Connect for Verifiable Credential presentation

## Abstract

This specification defines an extension of OpenID Connect to allow presentation of claims in the form of W3C Verifiable Credentials as part of the protocol flow in addition to claims provided in the `id_token` and/or via Userinfo responses.

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

There are two credential formats to VCs and VPs: JSON or JSON-LD. There are also two proof formats to VCs and VPs: JWT and Linked Data Proofs. Each of those formats has different properties and capabilites and each of them comes with different proof types. Proof formats are agnostic to the credential format chosen. However, the JSON credential format is commonly used with JSON Web Signatures (https://www.w3.org/TR/vc-data-model/#json-web-token). JSON-LD is commonly used with different kinds of Linked Data Proofs and JSON Web Signatures (https://www.w3.org/TR/vc-data-model/#json-ld). 

This specification defines standard claims to allow implementations to support all beforementioned assertion and proof formats. These claims can be used with any OpenID Connect Flows: as JWTs such as ID tokens, or as sets of JSON claims such as UserInfo Endpoint responses. 


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

Verifiable Credentials and Verifiable Presentations can be added to a OpenID Connect UserInfo response or an ID Token.

OAuth Authorization Servers can add `vp_jwt`, `vp_ldp`, `vc_jwt`, or `vc_ldp` claims to ID tokens in JWT format or UserInfo responses either in plain JSON or JWT-protected format.

An OP or AS MAY also include `vp_jwt`, `vp_ldp`, `vc_jwt`, or `vc_ldp` claims in the beforementioned assertions as aggregated or distributed claims (see Section 5.6.2 of the OpenID Connect specification [OpenID]).


## ID Token Extensions

W3C Verifiable Credentials specification defines two kinds of objects – Verifiable Credentials and Verifiable Presentations, and it also orthogonally defines two proof formats of these objects – JWT and Linked Data Proofs. Thus, there are four data types that different use cases could utilize.
 
This specification defines the following parameters to pass Verifiable Presentations or Verifiable Credentials signed as JWTs or using Linked Data Proofs:

- vc_jwt:  A claim whose value is a W3C Verifiable Credential object using the JWT representation, which is a JSON string.  The claim’s value may also be an array of W3C Verifiable Credential objects using the JWT representation if the use case calls for multiple JWT VCs.

- vp_jwt:  A claim whose value is a W3C Verifiable Presentation object using the JWT representation, which is a JSON string.  The claim’s value may also be an array of W3C Verifiable Presentation objects using the JWT representation if the use case calls for multiple JWT VPs.

- vc_ldp:  A claim whose value is a W3C Verifiable Credential object using the JSON-LD representation, which is a JSON object.  The claim’s value may also be an array of W3C Verifiable Credential objects using the JSON-LD representation if the use case calls for multiple JSON-LD VCs.

- vp_ldp:  A claim whose value is a W3C Verifiable Presentation object using the JSON-LD representation, which is a JSON object.  The claim’s value may also be an array of W3C Verifiable Presentation objects using the JSON-LD representation if the use case calls for multiple JSON-LD VPs.

Note that above claims have to be distinguished from `vp` or `vc` claims as defined in [JWT proof format](https://www.w3.org/TR/vc-data-model/#json-web-token). `vp` or `vc` claims contain those parts of the standard verifiable credentials and verifiable presentations where no explicit encoding rules for JWT exist. They are not meant to include complete verifiable credentials or verifiable presentations objects which is the purpose of the four claims defined in this specification.

This table shows the different combinations of covered by the claims defined in this specificaiton.

|  | vc_jwt | vp_jwt | vc_ldp | vp_ldp
|:----------------|:---------------|:---------------|:---------|:--------------------------|
| Object included in the claim | verifiable credential | verifiable presentation | verifiable credential | verifiable presentation 
| Proof format on the object| JWT | JWT | LD-Proof | LD-Proof

The next section illustrates how the `claims` parameter can be used for requesting verified presentations. It serves as a starting point to drive discussion about this aspect. There are other candidate approaches for this purpose. They will be evaluated as this draft evolves. 


## Requesting Verifiable Presentations

A RP requests a Verifiable Presentation using the `claims` parameter. 

### Verifiable Presentation object in id_token

A Verifiable Presentation embedded in an ID Token is requested by adding a element `vp_jwt` or `vp_ldp` to the `id_token` top level element of the `claims` parameter. This element must contain the following element:

`credential_types`
A string array containing a list of VC credential types the RP asks for. The OP shall respond with a presentation containing one credential of one of the listed types. 

Here is a non-normative example with `vp_jwt` claim: 

```json
{
   "id_token":{
      "acr":null,
      "vp_jwt":{
         "credential_types":[
            "https://www.w3.org/2018/credentials/examples/v1/IDCardCredential"
         ]
      }
   }
}
```

### Verifiable Credential object in id_token

A Verifiable Credential embedded in an ID Token is requested by adding a element `vc_jwt` or `vc_ldp` to the `id_token` top level element of the `claims` parameter. This element must contain a `credential_types` sub element as defined above.

Note that OP would first encode VPs/VCs using the rules defined in the Verifiable Credential specification either in JWT format or JSON-LD format, before passing encoded VPs/VCs as `vp_jwt`, `vp_ldp`, `vc_jwt`, or `vc_ldp` parameters as JWT claims or as sets of JSON claims.

#  Request Examples 
This section illustrates the response when W3C Verifiable Credentials objects are returned with JTWs such as inside ID Token.

## Self-Issued OP with Verifiable Presentation in ID Token
Below are the examples when W3C Verifiable Credentials are requested and returned inside ID Token as part of Self-Issued OP response. ID Token contains a `vp_jwt` or `vp_ldp` element with the Verifiable Presentation data, or a `vc_jwt` or `vc_ldp` element with the Verifiable Credential data. 

### Authentication request

The following is a non-normative example of how an RP would use the `claims` parameter to request the `vp_jwt` claim in the `id_token`:

```
  HTTP/1.1 302 Found
  Location: openid://?
    response_type=id_token
    &client_id=https%3A%2F%2Fclient.example.org%2Fcb
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &scope=openid
    &claims=claims=%7B%22id_token%22%3A%7B%22vc%22%3A%7B%22types%22%3A%5B%22https%3A%2F%
     2Fdid.itsourweb.org%3A3000%2Fsmart-credential%2FOntario-Health-Insurance-Plan
     %22%5D%7D%7D%7D
    &state=af0ifjsldkj
    &nonce=960848874
    &registration_uri=https%3A%2F%2F
      client.example.org%2Frf.txt%22%7D
      
```
#### claims parameter

In this case, the RP asks the OP to provide a VC of a certain type.  

```
{
    "id_token": {
      "vp_jwt": {
        "credential_types": ["https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan"]
      } 
    }
}
```

### ID Token with Verifiable Credentials signed as JWTs

Below is a non-normative example of ID Token that includes `vp_jwt` claim.

```
{
  "kid": "did:ion:EiC6Y9_aDaCsITlY06HId4seJjJ...b1df31ec42d0",
  "typ": "JWT",
  "alg": "ES256K"
}.{
   "iss":"https://self-issued.me",
   "aud":"https://book.itsourweb.org:3000/client_api/authresp/uhn",
   "iat":1615910538,
   "exp":1615911138,
   "sub":"did:ion:EiC6Y9_aDaCsITlY06HId4seJjJ-9...mS3NBIn19",
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
    "iss":"did:ion:EiC6Y9_aDaCsITlY06HId4seJjJ...b1df31ec42d0",
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

### ID Token with Verifiable Presentation signed using Linked Data Proofs

Below is a non-normative example of ID Token that includes `vp_ldp` claim.

```
{
   "iss":"https://self-issued.me",
   "aud":"https://book.itsourweb.org:3000/client_api/authresp/uhn",
   "iat":1615910538,
   "exp":1615911138,
   "sub":"did:ion:EiC6Y9_aDaCsITlY06HId4seJjJ...b1df31ec42d0",
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


# Authorization COde Flow
This section illustrates the response when W3C Verifiable Credentials objects are returned as JWTs from user_info endpoint responses.

### Authentication Request

```
  GET /authorize?
    response_type=code
    &client_id=s6BhdRkqt3 
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &scope=openid
    &claims=...
    &state=af0ifjsldkj
    &nonce=n-0S6_WzA2Mj HTTP/1.1
  Host: server.example.com
```

#### Claims parameter

```json
{
    "vp_ldp": {
      "claims":
      {
        "given_name": null,
        "family_name": null,
        "birthdate": null
      }
    }
}
```

### Authentication Response
```
HTTP/1.1 302 Found
  Location: https://client.example.org/cb?
    code=SplxlOBeZQQYbYS6WxSbIA
    &state=af0ifjsldkj
```

### Token Request
```
  POST /token HTTP/1.1
  Host: server.example.com
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

  grant_type=authorization_code
  &code=SplxlOBeZQQYbYS6WxSbIA
  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
```
### Token Response

### id_token

```json
{
  "iss": "http://server.example.com",
  "sub": "248289761001",
  "aud": "s6BhdRkqt3",
  "nonce": "n-0S6_WzA2Mj",
  "exp": 1311281970,
  "iat": 1311280970
}
```

### UserInfo Response with with Verifiable Presentation signed as JWTs

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

### UserInfo Response with Verifiable Presentation signed using Linked Data Proofs

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

## VC encoding options

### W3C Verifiable Credential in JWT format using external JWT proof

The following is a non-normative example of a W3C VC using the external [JWT proof format](https://www.w3.org/TR/vc-data-model/#json-web-token), i.e., standard W3C VC encoded as a JWT (base64url decoded JWT payload only). 

In this case the OP released a credential compatible with the eIDAS trust framework as requested by the RP (a swedish id card). 

```json
{
  "iss": "did:example:issuer",
  "sub": "did:example:holder",
  "jti": "http://example.edu/credentials/3732",
  "nbf": 1541493724,
  "iat": 1541493724,
  "exp": 1573029723,
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "type": [
      "VerifiableCredential",
      "IDCardredential"
    ],
    "issuer":{
      "name":"Skatteverket",
      "country":"SE"
    }
    "credentialSubject": {
      "given_name": "Fredrik",
      "family_name": "Strömberg",
      "birthdate": "1949-01-22",
      "place_of_birth": {
        "country": "SE",
        "locality": "Örnsköldsvik"
      },
      "nationality": "SE"
    }
  }
}
```

### W3C Verifiable Credential in JSON-LD format using internal proof

The following is a non-normative example of a W3C VC using the internal proof format. The proof property contains a JSON-LD Proof and uses the detached JWS encoding for the signature representation.

In this case the OP released a credential compatible with the eIDAS trust framework as requested by the RP (a swedish id card). 

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "https://example.com/credentials/1872",
  "type": [
    "VerifiableCredential",
    "IDCardredential"
  ],
  "issuer": {
    "id": "did:example:issuer",
    "name":"Skatteverket",
    "country":"SE"
  },
  "issuanceDate": "2010-01-01T19:23:24Z",
  "credentialSubject": {
    "given_name": "Fredrik",
    "family_name": "Strömberg",
    "birthdate": "1949-01-22",
    "place_of_birth": {
       "country": "SE",
       "locality": "Örnsköldsvik"
    },
     "nationality": "SE",
    "number": "4901224131",
    "date_of_issuance":"2010-03-23",
    "date_of_expiry":"2020-03-22"
  },
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2021-03-19T15:30:15Z",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PT8yCqVjj5ZHD0W36zsBQ47oc3El07WGPWaLUuBTOT48IgKI5HDoiFUt9idChT_Zh5s8cF_2cSRWELuD8JQdBw",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:example:issuer#keys-1"
  }
}
```

## VP encoding options

### W3C Verifiable Presentation in JWT format using external JWT proof

The following is a non-normative example of a W3C VP using the external [JWT proof format](https://www.w3.org/TR/vc-data-model/#json-web-token), i.e., standard W3C VP encoded as a JWT (base64url decoded JWT payload only):

```json
{
  "iss": "did:example:issuer",
  "sub": "did:example:holder",
  "jti": "http://example.edu/credentials/3732",
  "nbf": 1541493724,
  "iat": 1541493724,
  "exp": 1573029723,
  "nonce": "=§§@34fdfd3!",
  "vp": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "type": [
      "VerifiablePresentation",
    ],
    "verifiableCredential": [ "eyJhbGc..." ]
  }
}
```

### W3C Verifiable Presentation in JSON-LD format using internal proof
The following is a non-normative example of a W3C VP using the internal proof format. The proof property contains a JSON-LD Proof and uses the detached JWS encoding for the signature representation.

In this case the OP selectively disclosed claims from a credential compatible with the eIDAS trust framework as requested by the RP (a swedish id card). 

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "type": [
    "VerifiablePresentation"
  ],
  "verifiableCredential": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "id": "https://example.com/credentials/1872",
      "type": [
        "VerifiableCredential",
        "IDCardCredential"
      ],
      "issuer": {
        "id": "did:example:issuer"
      },
      "issuanceDate": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "given_name": "Fredrik",
        "family_name": "Strömberg",
        "birthdate": "1949-01-22"
      },
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2021-03-19T15:30:15Z",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PT8yCqVjj5ZHD0W36zsBQ47oc3El07WGPWaLUuBTOT48IgKI5HDoiFUt9idChT_Zh5s8cF_2cSRWELuD8JQdBw",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:example:issuer#keys-1"
      }
    }
  ],
  "id": "ebc6f1c2",
  "holder": "did:example:holder",
  "proof": {
    "type": "Ed25519Signature2018",
    "created": "2021-03-19T15:30:15Z",
    "challenge": "()&)()0__sdf",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..GF5Z6TamgNE8QjE3RbiDOj3n_t25_1K7NVWMUASe_OEzQV63GaKdu235MCS3hIYvepcNdQ_ZOKpGNCf0vIAoDA",
    "proofPurpose": "authentication",
    "verificationMethod": "did:example:holder#key-1"
  }
}
```


### Related Issues
- https://bitbucket.org/openid/connect/issues/1206/how-to-support-ld-proofs-in-verifiable#comment-60051830
