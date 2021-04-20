# OpenID Connect for W3C Verifiable Credential Objects

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

There are two formats of VCs and VPs: JWT and JSON-LD. Each of those formats has different properties and capabilites and each of them comes with different proof types. The JWT format can be used with JSON Web Signatures (https://www.w3.org/TR/vc-data-model/#json-web-token). JSON-LD is used with different kinds of Linked Data Proofs and JSON Web Signatures (https://www.w3.org/TR/vc-data-model/#json-ld).

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

This specifications defines mechanims to embed verifiable credentials and presentations or references to verifiable credentials and presentations into ID Tokens and Userinfo responses based on the aggregated and distributed claims facility as defined in OpenID Connect Core.   

Verifiable credentials and presentations are requested using the `claims` parameter. The RP MAY request the OP to provide certain credential types, optionally with selective disclosure constraints. It MAY also just request End-User claims, like `given_name`, and leave it to the OP to decide whether it provides those claims as Standard OpenID Connect claims (asserted by the OP) or via Verifiable Presentations or Credentials. 

If the verifiable credential or presentation is provided as aggregated claims, the respective object is embeded using as source object within the `_claim_sources` array as defined in OpenID Connect Core. 

If the verifiable credential or presentation is provided as distributed claims, the respective object is referenced via the `endpoint` field of a source object within the  `_claim_sources` array. The RP obtains the object by sending a GET request to this endpoint utilizing the optionally provided access token to authorize the call. 

The verifiable credential or presentation is provided as self contained object in JWT or JSON-LD format. The object and proof format depend on the capabilities of the OP and the configuration of the RP set up using client metadata. 

## Requesting Verifiable Presentations

A RP requests a Verifiable Presentation using the `claims` parameter. 

### Requesting certain credential types

#### Verifiable Credentials

A Verifiable Credential is requested by adding a `verifiable_credential` element to the `id_token` or `userinfo` top level element of the `claims` parameter. This element must contain the following element:

`credential_types`
A string array containing a list of VC credential types the RP asks for. The OP shall respond with a presentation containing one credential of one of the listed types. 

Here is are examples requesting verifiable credential to be added to the ID Token: 

```json
{
   "id_token":{
      "verifiable_credential":{
         "credential_types":[
            "https://www.w3.org/2018/credentials/examples/v1/IDCardCredential"
         ]
      } 
   }
}
```

#### Verifiable Presentations

A Verifiable Presentation is requested by adding an element `verifiable_presentation` to the `id_token` or `userinfo` top-level element of the `claims` parameter. This element contains the following sub elements:

`credential_types`
Object array containing definitions of credential types the RP wants to obtain along with an (optional) definition of the claims from the respective credential type the RP is requesting. Each of those object has the following fields:

* `type` - String denoting a credential type

* `claims` - An object determining the claims the RP wants to obtain using the same notation as used underneath `id_token`. 

Here is an example:

```json
{
   "id_token":{
      "verifiable_presentation":{
        "credential_types":[
         {
            "type":"https://www.w3.org/2018/credentials/examples/v1/IDCardCredential",
            "claims":{
               "given_name":null,
               "family_name":null,
               "birthdate":null
            }
         }
      ]
}
```
### Requesting Claims

The RP MAY request End-User claims using the syntax as defined in the OpenID Connect Core. In this case, the OP may decide whether these claims are provided as OpenID Connect claims or via a Verifiable Presentation. 

Here is an example:

```json
{
   "id_token":{
      "given_name":null,
      "family_name":null,
      "birthdate":null
   }
}
```

## VC/VP Delivery

Verifiable Credentials and Verifiable Presentations are provided as aggregated or distributed claims either in ID Token or Userinfo response (as requested by the RP). The OP determines what mechanism to use for each presentation or credential.

This specification uses the `_claim_names_` element as is. It is used to map claims as requested by the RP to the respective source in this case a verifiable credential or presentation. 

This specification introduces a new top level claim `_credential_types`, which maps credential types as requested by the RP to  source used to provide the respective credential. 

This specification extends the syntax for aggregated and disctributed claims sources as follows:

Aggregated and distributed claims sources:

* a `format` field is added containing the format of the verifiable credential or presentation. `vp_jwt` and `vc_jwt` denote a credential or presentation in JWT format, respectively. `vc_ldp` and `vp_ldp` denote a credential or presentation in JSON-LD, respectively. All content is provided in the claim source object as is without further encoding. For backward compability, the format `jwt` is used to denote standard OIDC aggregated/distributed claims. 
* a `value` element containing the actual presentation or credential in case of an aggregated claim for verifiable presentations or credentials. 

Here is an example:

```json
{
   "iss":"https://self-issued.me",
   "sub":"248289761001",
   "_claim_names":{
      "family_name":"src1",
      "alumniof":"src2",
      "nationality":"src3",
      "data_of_birth":"src4"
   },
   "_credential_types":{
      "https://www.w3.org/2018/credentials/examples/v1/AlumniCredential":[
         "src1",
         "src2"
      ],
      "https://www.w3.org/2018/credentials/examples/v1/IDCardCredential":[
         "src3",
         "src4"
      ]
   },
   "_claim_sources":{
      "src1":{
         "format":"vp_jwt",
         "value":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5vdGhlcm9wLmNvbSIsInN1YiI6ImU4MTQ4NjAzLTg5MzQtNDI0NS04MjViLWMxMDhiOGI2Yjk0NSIsInZlcmlmaWVkX2NsYWltcyI6eyJ2ZXJpZmljYXRpb24iOnsidHJ1c3RfZnJhbWV3b3JrIjoiaWFsX2V4YW1wbGVfZ29sZCJ9LCJjbGFpbXMiOnsiZ2l2ZW5fbmFtZSI6Ik1heCIsImZhbWlseV9uYW1lIjoiTWVpZXIiLCJiaXJ0aGRhdGUiOiIxOTU2LTAxLTI4In19fQ.FArlPUtUVn95HCExePlWJQ6ctVfVpQyeSbe3xkH9MH1QJjnk5GVbBW0qe1b7R3lE-8iVv__0mhRTUI5lcFhLjoGjDS8zgWSarVsEEjwBK7WD3r9cEw6ZAhfEkhHL9eqAaED2rhhDbHD5dZWXkJCuXIcn65g6rryiBanxlXK0ZmcK4fD9HV9MFduk0LRG_p4yocMaFvVkqawat5NV9QQ3ij7UBr3G7A4FojcKEkoJKScdGoozir8m5XD83Sn45_79nCcgWSnCX2QTukL8NywIItu_K48cjHiAGXXSzydDm_ccGCe0sY-Ai2-iFFuQo2PtfuK2SqPPmAZJxEFrFoLY4g"
      },
      "src2":{
         "format":"vp_jwt",
         "endpoint":"https://op.example.com/presentations/1234564",
         "access_token":"ksj3n283dkeafb76cdef"
      },
      "src3":{
         "format":"vp_ldp",
         "value":{
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
      },
      "src4":{
         "format":"vp_ldp",
         "endpoint":"https://op.example.com/presentations/1234567",
         "access_token":"ksj3n283dkeafb76caaa"
      }
   }
}
```
# Request Examples
## SIOP 
This section illustrates the protocol flow for the case of communication through the front channel only (SIOP) where the `id_token` is a Verifiable Presentation as well. 

### Authentication request

The following is a non-normative example of how an RP would use the `claims` parameter to request the `vp` claim in the `id_token`:

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
      "verifiable_presentation": {
        "credential_types":[
         {
            "type":"https://www.w3.org/2018/credentials/examples/v1/IDCardCredential"
         }
        ]
      } 
    }
}
```

### Authentication Response 

The successful authentication response contains an `id_token` and `state`.
```
  HTTP/1.1 302 Found
  Location: https://client.example.org/cb#
    id_token=...
    &state=af0ifjsldkj
      
```
### Verifiable Presentation as aggregated claim

The ID Token contains a `src1` element with the Verifiable Credential data. 

```json
{
   "iss":"https://book.itsourweb.org:3000/wallet/wallet.html",
   "aud":"https://book.itsourweb.org:3000/client_api/authresp/uhn",
   "iat":1615910538,
   "exp":1615911138,
   "sub":"urn:uuid:68f874e2-377c-437f-a447-b304967ca351",
   "auth_time":1615910535,
   "nonce":"960848874",
   "sub_jwk":{
      "crv":"P-384",
      "ext":true,
      "key_ops":[
         "verify"
      ],
      "kty":"EC",
      "x":"jf3a6dquclZ4PJ0JMU8RuucG9T1O3hpU_S_79sHQi7VZBD9e2VKXPts9lUjaytBm",
      "y":"38VlVE3kNiMEjklFe4Wo4DqdTKkFbK6QrmZf77lCMN2x9bENZoGF2EYFiBsOsnq0"
   },
   "_credential_types":{
      "https://www.w3.org/2018/credentials/examples/v1/IDCardCredential":[
         "src1"
      ]
   },
   "_claim_sources":{
      "src1":{
         "format":"vp_jwt",
         "value":"eyJraWQiOiJkaWQ6aW9uOkVpQzZZOV9hRGFDc0lUbFkwNkhJZDRzZUpq...5SRU16ZEdsUWR6SkdTbWNpZlgwIn0.nwxW-8GVL0msMAhZESDZkGC3U00iJgqQXyz3cpfQXIyzqD82A8Eko7nh-7U8-CZ3gl6tdLgxSJEc6nJM7G_-oQ"
      }
   }
}
```

The `value` element is the VP containing the underlying VC in the `verifiableCredential` element, which decodes to

```json
{
   "sub":"urn:uuid:68f874e2-377c-437f-a447-b304967ca351",
   "iss":"https://book.itsourweb.org:3000/ohip",
   "iat":1615910155,
   "exp":1616082955,
   "aud":"https://book.itsourweb.org:3000/wallet/wallet.html",
   "jti":"urn:uuid:7fe918f0-c172-434c-9d9b-3d21d45b3e62",
   "vc":{
      "@context":[
         "https://www.w3.org/2018/credentials/v1",
         "https://ohip.ontario.ca/v1"
      ],
      "type":[
         "VerifiableCredential",
         "https://did.itsourweb.org:3000/smart-credential/Ontario-Health-Insurance-Plan"
      ],
      "description":"OHIP status",
      "credentialSubject":{
         "healthNumber":"1122334455",
         "versionNumber":"NV",
         "dateOfBirth":"1995/07/10",
         "firstName":"Jane",
         "lastName":"Doe",
         "postalCode":"M6H3B3",
         "status":"OK"
      }
   }
}
```

### Verifiable Presentation as distributed claim

This example shows an ID Token containing a reference to a verifiable presentation in the `src1` element:

```json
{
   "iss":"https://book.itsourweb.org:3000/wallet/wallet.html",
   "aud":"https://book.itsourweb.org:3000/client_api/authresp/uhn",
   "iat":1615910538,
   "exp":1615911138,
   "sub":"urn:uuid:68f874e2-377c-437f-a447-b304967ca351",
   "auth_time":1615910535,
   "nonce":"960848874",
   "sub_jwk":{
      "crv":"P-384",
      "ext":true,
      "key_ops":[
         "verify"
      ],
      "kty":"EC",
      "x":"jf3a6dquclZ4PJ0JMU8RuucG9T1O3hpU_S_79sHQi7VZBD9e2VKXPts9lUjaytBm",
      "y":"38VlVE3kNiMEjklFe4Wo4DqdTKkFbK6QrmZf77lCMN2x9bENZoGF2EYFiBsOsnq0"
   },
   "_credential_types":{
      "https://www.w3.org/2018/credentials/examples/v1/IDCardCredential":[
         "src1"
      ]
   },
   "_claim_sources":{
     "src1":{
         "format":"vp_jwt",
         "endpoint":"https://op.example.com/presentations/1234564",
         "access_token":"ksj3n283dkeafb76cdef"
      }
   }  
}
```

The RP obtains the verifiable presentation by sending a GET request to URL in the `endpoint` element. 

```
GET /presentations/1234564 HTTP/1.1
Host: op.example.com
Authorization: BEARER ksj3n283dkeafb76cdef

HTTP/1.1 200 OK
Content-Type: application/jwt

eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3NlcnZlci5vdGhlcm9wLmNvbSIsInN1YiI6ImU4MTQ4NjAzLTg5MzQtNDI0NS04MjViLWMxMDhiOGI2Yjk0NSIsInZlcmlmaWVkX2NsYWltcyI6eyJ2ZXJpZmljYXRpb24iOnsidHJ1c3RfZnJhbWV3b3JrIjoiaWFsX2V4YW1wbGVfZ29sZCJ9LCJjbGFpbXMiOnsiZ2l2ZW5fbmFtZSI6Ik1heCIsImZhbWlseV9uYW1lIjoiTWVpZXIiLCJiaXJ0aGRhdGUiOiIxOTU2LTAxLTI4In19fQ.FArlPUtUVn95HCExePlWJQ6ctVfVpQyeSbe3xkH9MH1QJjnk5GVbBW0qe1b7R3lE-8iVv__0mhRTUI5lcFhLjoGjDS8zgWSarVsEEjwBK7WD3r9cEw6ZAhfEkhHL9eqAaED2rhhDbHD5dZWXkJCuXIcn65g6rryiBanxlXK0ZmcK4fD9HV9MFduk0LRG_p4yocMaFvVkqawat5NV9QQ3ij7UBr3G7A4FojcKEkoJKScdGoozir8m5XD83Sn45_79nCcgWSnCX2QTukL8NywIItu_K48cjHiAGXXSzydDm_ccGCe0sY-Ai2-iFFuQo2PtfuK2SqPPmAZJxEFrFoLY4g  
```

## Standard OpenID Connect (backchannel)

This section illustrates the protocol flow for the case of communication using frontchannel and backchannel (utilizing the authorization code flow).

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
    "id_token": {
      "verifiable_presentation": {
        "credential_types":[
         {
            "type":"https://www.w3.org/2018/credentials/examples/v1/IDCardCredential"
         }
        ]
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

```
{
   "access_token": "SlAV32hkKG",
   "token_type": "Bearer",
   "refresh_token": "8xLOxBtZp8",
   "expires_in": 3600,
   "id_token": "eyJ0 ... NiJ9.eyJ1c ... I6IjIifX0.DeWt4Qu ... ZXso"
   "vp_token": "wl93lqt7_R...Cf0h"
  }
```

### Verifiable Presentation as aggregated claim

```json
{
   "iss":"http://server.example.com",
   "sub":"248289761001",
   "aud":"s6BhdRkqt3",
   "iat":1615910538,
   "exp":1615911138,
   "auth_time":1615910535,
   "nonce":"960848874",
   "sub_jwk":{
      "crv":"P-384",
      "ext":true,
      "key_ops":[
         "verify"
      ],
      "kty":"EC",
      "x":"jf3a6dquclZ4PJ0JMU8RuucG9T1O3hpU_S_79sHQi7VZBD9e2VKXPts9lUjaytBm",
      "y":"38VlVE3kNiMEjklFe4Wo4DqdTKkFbK6QrmZf77lCMN2x9bENZoGF2EYFiBsOsnq0"
   },
   "_credential_types":{
      "https://www.w3.org/2018/credentials/examples/v1/AlumniCredential":[
         "src1"
      ]
   },
   "_claim_sources":{
    "src1":{
         "format":"vp_ldp",
         "value":{
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
      }
   }
}
```

`src1` contains the a verifiable presentation in JSON-LD format. 

### Verifiable Presentation as distributed claim

The presentation can also be provided using a distributed claims source. 

```json
{
   "iss":"http://server.example.com",
   "sub":"248289761001",
   "aud":"s6BhdRkqt3",
   "iat":1615910538,
   "exp":1615911138,
   "auth_time":1615910535,
   "nonce":"960848874",
   "sub_jwk":{
      "crv":"P-384",
      "ext":true,
      "key_ops":[
         "verify"
      ],
      "kty":"EC",
      "x":"jf3a6dquclZ4PJ0JMU8RuucG9T1O3hpU_S_79sHQi7VZBD9e2VKXPts9lUjaytBm",
      "y":"38VlVE3kNiMEjklFe4Wo4DqdTKkFbK6QrmZf77lCMN2x9bENZoGF2EYFiBsOsnq0"
   },
   "_credential_types":{
      "https://www.w3.org/2018/credentials/examples/v1/IDCardCredential":[
         "src1"
      ]
   },
   "_claim_sources":{
     "src1":{
         "format":"vp_ldp",
         "endpoint":"https://op.example.com/presentations/1234564",
         "access_token":"ksj3n283dkeafb76cdef"
      }
   }
}
```

The RP obtains the presentation by sending a GET request to the URL denoted in `endpoint`.

```
GET /presentations/1234564 HTTP/1.1
Host: op.example.com
Authorization: BEARER ksj3n283dkeafb76cdef

HTTP/1.1 200 OK
Content-Type: application/ld+json

{
   "format":"vp_ldp",
   "value":{
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
}
```

# Alternatives
- VP as JWT embedded in an ID Token via presentation exchange: https://hackmd.io/wljYjkzfTmKVW0bX91o_Iw?view
- VP in all formats and with all proof formats embedded in id token

### Related Issues
- https://bitbucket.org/openid/connect/issues/1206/how-to-support-ld-proofs-in-verifiable#comment-60051830
