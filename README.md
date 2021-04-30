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

W3C Verifiable Credential Objects

Both verifiable credential and verifiable presentation

## Introduction

This specification extends OpenID Connect with support for presentation of claims via W3C Verifiable Credentials. This allows existing OpenID Connect RPs to extends their reach towards claims sources asserting claims in this format. It also allows new applications built using Verifiable Credentials to utilize OpenID Connect as integration and interoperability layer towards credential holders. 

This specification supports two ways to present Verifiable Credentials. Its is possible to provide the RP directly with a Verificable Credential or to use a Verifiable Presentation.

The Verifiable Credential (VC) can be used to assert claims towards a Verifier under some circumstances. Either the credential is a bearer credential, i.e. it is not bound to a certain secret that requires proof of control when presenting the credential, or the link between the subject of the credential and the presenter of the credential can be established by other means, e.g. by proofing control over the subject's DID in the same process. 

Verifiable Presentations (VP) are used to present claims along with cryptographic proofs of the link between presenter and subject of the verifiable credentials it contains. A verifiable presentation can contain a subset of claims asserted in a certain credential (selective disclosure) and it can assemble claims from different credentials. 

There are two credential formats to VCs and VPs: JSON or JSON-LD. There are also two proof formats to VCs and VPs: JWT and Linked Data Proofs. Each of those formats has different properties and capabilites and each of them comes with different proof types. Proof formats are agnostic to the credential format chosen. However, the JSON credential format is commonly used with JSON Web Signatures (https://www.w3.org/TR/vc-data-model/#json-web-token). JSON-LD is commonly used with different kinds of Linked Data Proofs and JSON Web Signatures (https://www.w3.org/TR/vc-data-model/#json-ld). 

This specification defines standard claims and a separate artifact to allow implementations to support all beforementioned assertion and proof formats. These claims can be used with any OpenID Connect Flows: as JWTs such as ID tokens, or as sets of JSON claims such as UserInfo Endpoint responses. 


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

W3C Verifiable Credentials specification defines two kinds of objects – Verifiable Credentials and Verifiable Presentations, and it also orthogonally defines two proof formats of these objects – JWT and Linked Data Proofs. Thus, there are four data types that different use cases could utilize.

This specification defines the JWT parameters to pass VPs and VCs signed as JWTs or using Linked Data Proofs.

This specifications also introduces a new artifact VP Token and VC Token to provide VPs and VCs to RPs:

### JWT parameters extention

This specification introduces the following JWT parameters:

- vc_jwt:  A claim whose value is a W3C Verifiable Credential object using the JWT representation, which is a JSON string.  The claim’s value may also be an array of W3C Verifiable Credential objects using the JWT representation if the use case calls for multiple JWT VCs.

- vp_jwt:  A claim whose value is a W3C Verifiable Presentation object using the JWT representation, which is a JSON string.  The claim’s value may also be an array of W3C Verifiable Presentation objects using the JWT representation if the use case calls for multiple JWT VPs.

- vc_ldp:  A claim whose value is a W3C Verifiable Credential object using the JSON-LD representation, which is a JSON object.  The claim’s value may also be an array of W3C Verifiable Credential objects using the JSON-LD representation if the use case calls for multiple JSON-LD VCs.

- vp_ldp:  A claim whose value is a W3C Verifiable Presentation object using the JSON-LD representation, which is a JSON object.  The claim’s value may also be an array of W3C Verifiable Presentation objects using the JSON-LD representation if the use case calls for multiple JSON-LD VPs.

These claims can be added to ID Tokens, Userinfo responses as well as Access Tokens and Introspection response. They MAY also be included as aggregated or distributed claims (see Section 5.6.2 of the OpenID Connect specification [OpenID]).

Note that above claims have to be distinguished from `vp` or `vc` claims as defined in [JWT proof format](https://www.w3.org/TR/vc-data-model/#json-web-token). `vp` or `vc` claims contain those parts of the standard verifiable credentials and verifiable presentations where no explicit encoding rules for JWT exist. They are not meant to include complete verifiable credentials or verifiable presentations objects which is the purpose of the four claims defined in this specification.

This table shows the different combinations of covered by the claims defined in this specificaiton.

|  | vc_jwt | vp_jwt | vc_ldp | vp_ldp
|:----------------|:---------------|:---------------|:---------|:--------------------------|
| Object included in the claim | verifiable credential | verifiable presentation | verifiable credential | verifiable presentation 
| Proof format on the object| JWT | JWT | LD-Proof | LD-Proof

### New Artifacts extention

This specifications introduces the following new artifacts:

* VP Token: a Verifiable Presentation is provided in a separate artifact designated as "VP Token". Such a token is provided to the RP in addition to an `id_token` in the `vp_token` parameter. VP Tokens support Verifiable Presentations in JSON-LD as well JWT format including all respective proof formats. They also allow to sign ID Token and Verifiable Presentation with different key. 
* VC Token: a Verifiable Credential is provided in a separate artifact designated as "VC Token". Such a token is provided to the RP in addition to an `id_token` in the `vc_token` parameter. VC Tokens support Verifiable Presentations in JSON-LD as well JWT format including all respective proof formats.

This table shows the different combinations of signatures on id token, VC, and VP and how the binding of the VC or VP with the holder is validated by the RP.

| ID Token Signer | `vc` claim in ID Token | `vp` claim in ID Token | `vc_token` | `vp_token` 
|:----------------|:---------------|:---------------|:---------|:--------------------------|
| Holder of the VC | bearer credential or same did in `sub` and credential | vp signed by holder | bearer credential or same did in `sub` and credential + `vc_hash` | VP signed by holder + `vp_hash` 
| Other entity (e.g. OP)| bearer credential | n/a | bearer credential  | VP signed by holder + `vp_hash`


## Requesting W3C Verifiable Credential Objects 

### Requesting W3C Verifiable Credential Objects using the `claims` parameter

The next section illustrates how the `claims` parameter can be used for requesting verified presentations. It serves as a starting point to drive discussion about this aspect. There are other candidate approaches for this purpose. They will be evaluated as this draft evolves. 

#### Requesting Verifiable Presentations

A Verifiable Presentation embedded in an ID Token is requested by adding a element `vp_jwt` or `vp_ldp` to the `id_token` top level element of the `claims` parameter. This element must contain the following element:

`credential_types`
A string array containing a list of VC credential types the RP asks for. The OP shall respond with a presentation containing one credential of one of the listed types. 

`userinfo`


Here is a non-normative example with `vp_jwt` claim: 

```json
{
   "id_token":{
      "acr":null,
      "vp_jwt":{
         "credential_types":[
            https://example.org/examples#UniversityDegreeCredential"
         ]
      }
   }
}
```

Note: [DIF Presentation Exchange](https://identity.foundation/presentation-exchange/) can also be sed to request W3C Verifiable Credentials Objects. Interoperability with `claims` parameter based requests is being discussed.

#### Requesting Verifiable Credentials

A Verifiable Credential embedded in an ID Token is requested by adding a element `vc_jwt` or `vc_ldp` to the `id_token` top level element of the `claims` parameter. This element must contain a `credential_types` sub element as defined above.

Note that OP would first encode VPs/VCs using the rules defined in the Verifiable Credential specification either in JWT format or JSON-LD format, before passing encoded VPs/VCs as `vp_jwt`, `vp_ldp`, `vc_jwt`, or `vc_ldp` parameters as JWT claims or as sets of JSON claims.

### Requesting a VP Token

A VP Token is requested by adding a new top level element `vp_token` to the `claims` parameter. This element contains the following sub elements:

`credential_types`
Object array containing definitions of credential types the RP wants to obtain along with an (optional) definition of the claims from the respective credential type the RP is requesting. Each of those object has the following fields:

* `type` - String denoting a credential type

* `claims` - An object determining the claims the RP wants to obtain using the same notation as used underneath `id_token`. 

`format`
String designating the VP format. Predefined values are `jwt` and `json-ld`.

`proof_format`
[TBD]

Here is an example:

```json
{
   "id_token":{
      "acr":null
   },
   "vp_token":{
      "format":"json-ld",
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
}
```

### Requesting a VC Token

A VP Token is requested by adding a new top level element `vc_token` to the `claims` parameter. This element must contain a `credential_types` sub element as defined above.

### VP Token/VC Token delivery

`vp_token` and/or `vc_token` are provided in the same response as the `id_token`. Depending on the response type, this can be either the authentication response or the token response. Authentication event information is conveyed via the id token while it's up to the RP to determine what (additional) claims are allocated to `id_token` and `vp_token`, respectively, via the `claims` parameter. 

If the `vp_token` or `vc_token` is returned in the frontchannel, a hash of the respective token MUST be included in `id_token` (see next chapter).

ToDo: Add a text that VP Token/VC Token can be returned from the userInfo endpoint

### New vp_hash / vc_hash parameters

`vp_hash`
OPTIONAL. Hash value of `vp_token` that represents the W3C VP. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the `vp_token` value, where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, hash the vp_token value with SHA-256, then take the left-most 128 bits and base64url encode them. The `vp_hash` value is a case sensitive string.

`vc_hash`
OPTIONAL. Hash value of `vc_token` that represents the W3C VC. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the `vc_token` value, where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, hash the `vc_token` value with SHA-256, then take the left-most 128 bits and base64url encode them. The `vc_hash` value is a case sensitive string.


##  Examples 

This section illustrates examples when W3C Verifiable Credentials objects are requested using `claims` parameter and returned inside ID Tokens.

### Self-Issued OpenID Provider with Verifiable Presentation in ID Token 

Below are the examples when W3C Verifiable Credentials are requested and returned inside ID Token as part of Self-Issued OP response. ID Token contains a `vp_jwt` or `vp_ldp` element with the Verifiable Presentation data. It can also contain `vc_jwt` or `vc_ldp` element with the Verifiable Credential data. 

#### Authentication request

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
#### `claims` parameter (`vp_jwt`)

Below is a non-normative example of how the `claims` parameter can be used for requesting verified presentations signed as a JWT.

```
{
    "id_token": {
      "vp_jwt": {
        "credential_types": ["https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan"]
      } 
    }
}
```

#### Authentication Response (`vp_jwt`)

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

#### `claims` parameter (`vp_ldp`)

Below is a non-normative example of how the `claims` parameter can be used for requesting verified presentations signed as Linked Data Proofs.

```
{
    "id_token": {
      "vp_ldp": {
        "credential_types": ["https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan"],
         "claims":
        {
          "given_name": null,
          "family_name": null,
          "birthdate": null
        }
      } 
    }
}
```

#### Authentication Response (`vp_ldp`)

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

### Authorization Code Flow with Verifiable Presentation in ID Token (vp_jwt)

Below are the examples when W3C Verifiable Credentials are requested and returned inside ID Token as part of Authorization Code flow. ID Token contains a `vp_jwt` or `vp_ldp` element with the Verifiable Presentation data. It can also contain `vc_jwt` or `vc_ldp` element with the Verifiable Credential data. 

#### Authentication Request

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

#### Claims parameter (vp_jwt)

Below is a non-normative example of how the `claims` parameter can be used for requesting verified presentations signed as JWT.

```json
{
   "id_token":
    {
      "vp_jwt": {
       "credential_types": ["https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan"]
      }
    }
}
```

#### Authentication Response

```
HTTP/1.1 302 Found
  Location: https://client.example.org/cb?
    code=SplxlOBeZQQYbYS6WxSbIA
    &state=af0ifjsldkj
```

#### Token Request

```
  POST /token HTTP/1.1
  Host: server.example.com
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

  grant_type=authorization_code
  &code=SplxlOBeZQQYbYS6WxSbIA
  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
```

#### Authentication Response (`vp_ldp`)

ID Token would be same as the example in the Self-Issued OP with Verifiable Presentation in ID Token, Authentication Response (`vp_jwt`) section.


#### Claims parameter (vp_ldp)

Below is a non-normative example of how the `claims` parameter can be used for requesting verified presentations signed as Linked Data Proofs.

```json
{
   "id_token":
    {
      "vp_ldp": {
        "credential_types": ["https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan"]
        "claims":
        {
          "given_name": null,
          "family_name": null,
          "birthdate": null
        }
      }
    }
}
```

#### Authentication Response (`vp_ldp`)

ID Token would be same as the example in the Self-Issued OP with Verifiable Presentation in ID Token, Authentication Response (`vp_ldp`) section.


### Authorization Code Flow with Verifiable Presentation returned from the UserInfo endpoint

Below are the examples when verifiable presentation is requested and returned from the UserInfo endpoint as part of OpenID Connect Authorization Code Flow. UserInfo response contains a `vp_jwt` or `vp_ldp` element with the Verifiable Presentation data. It can also contain `vc_jwt` or `vc_ldp` element with the Verifiable Credential data. 

#### Authentication Request

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

#### Claims parameter (vp_jwt)

Below is a non-normative example of how the `claims` parameter can be used for requesting verified presentations signed as JWT.

```json
{
   "userinfo":
    {
      "vp_jwt": {
      "credential_types": ["https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan"]       
      }
    },
   "id_token":
    {
     "auth_time": {"essential": true},
    }
}
```


#### Authentication Response

```
HTTP/1.1 302 Found
  Location: https://client.example.org/cb?
    code=SplxlOBeZQQYbYS6WxSbIA
    &state=af0ifjsldkj
```

#### Token Request

```
  POST /token HTTP/1.1
  Host: server.example.com
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

  grant_type=authorization_code
  &code=SplxlOBeZQQYbYS6WxSbIA
  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
```

#### Token Response

##### id_token

```json
{
  "iss": "http://server.example.com",
  "sub": "248289761001",
  "aud": "s6BhdRkqt3",
  "nonce": "n-0S6_WzA2Mj",
  "exp": 1311281970,
  "iat": 1311280970,
  "auth_time": 1615910535
}
```

##### UserInfo Response (vp_jwt)

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

JWT inside `vp_jwt` claim when decoded equals to a verifiable presentation in Self-Issued OP with Verifiable Presentation in ID Token, Authentication Response (`vp_jwt`) section.

#### Claims parameter (vp_ldp)

Below is a non-normative example of how the `claims` parameter can be used for requesting verified presentations signed as Linked Data Proofs.

```json
{
   "userinfo":
    {
      "vp_ldp": {
       "credential_types": ["https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan"]
       "claims":
        {
          "given_name": null,
          "family_name": null,
          "birthdate": null
        }
      }
    },
   "id_token":
    {
     "auth_time": {"essential": true},
    }
}
```
#### Token Response

##### id_token

```json
{
  "iss": "http://server.example.com",
  "sub": "248289761001",
  "aud": "s6BhdRkqt3",
  "nonce": "n-0S6_WzA2Mj",
  "exp": 1311281970,
  "iat": 1311280970,
  "auth_time": 1615910535
}
```

### UserInfo Response  (vp_ldp)

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

## SIOP with vp_token
This section illustrates the protocol flow for the case of communication through the front channel only (like in SIOP).

### Authentication request

The following is a non-normative example of how an RP would use the `claims` parameter to request claims in the `vp_token`:

```
  HTTP/1.1 302 Found
  Location: openid://?
    response_type=id_token
    &client_id=https%3A%2F%2Fclient.example.org%2Fcb
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &scope=openid
    &claims=...
    &state=af0ifjsldkj
    &nonce=n-0S6_WzA2Mj
    &registration_uri=https%3A%2F%2F
      client.example.org%2Frf.txt%22%7D
      
```

#### claims parameter

```json
{
    "vp_token": {
      "format": "json-ld",
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

The successful authentication response contains a `vp_token` parameter along with  `id_token` and `state`.
```
  HTTP/1.1 302 Found
  Location: https://client.example.org/cb#
    id_token=eyJ0 ... NiJ9.eyJ1c ... I6IjIifX0.DeWt4Qu ... ZXso
    &vp_token=...
    &state=af0ifjsldkj
      
```

#### id_token

This example shown an ID Token containing a `vp_hash`:

```json
{
   "iss":"https://book.itsourweb.org:3000/wallet/wallet.html",
   "aud":"https://book.itsourweb.org:3000/client_api/authresp/uhn",
   "iat":1615910538,
   "exp":1615911138,
   "sub":"urn:uuid:68f874e2-377c-437f-a447-b304967ca351",
   "auth_time":1615910535,
   "vp_hash":"77QmUPtjPfzWtF2AnpK9RQ",
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
   }
}
```

#### vp_token content

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
    "vp_token": {
      "format": "json-ld",
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

#### id_token

```json
{
  "iss": "http://server.example.com",
  "sub": "248289761001",
  "aud": "s6BhdRkqt3",
  "nonce": "n-0S6_WzA2Mj",
  "exp": 1311281970,
  "iat": 1311280970,
  "vp_hash": "77QmUPtjPfzWtF2AnpK9RQ"
}
```

#### vp_token

The VP token content is the same as in the SIOP vp_token example. 


### Related Issues
- https://bitbucket.org/openid/connect/issues/1206/how-to-support-ld-proofs-in-verifiable#comment-60051830
