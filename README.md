# OpenID Connect vp_token response parameter extension 

## Abstract

This specification defines the additional OpenID Connect authentication response parameter `vp_token`. The new parameter allows OpenID Connect OPs to provide RPs with End-User claims as W3C Verifiable Presentations or W3C Verifiable Credentials in addition to claims provided in the`id_token` and/or via Userinfo responses.

## Authors

- Oliver Terbu (ConsenSys Mesh)
- Torsten Lodderstedt (yes.com)
- Kristina Yasuda (Microsoft)
- Adam Lemmon (Trybe.ID)
- Tobias Looker (Mattr)

## Introduction

Notes:
- this should really start with the explanation of the role signatures play in VCs (can be both JSON or JSON-LD) and that there are two widely used proof types (JWTs and LD-proofs)
- Explain why is there a need for this extension?

## Overview
- RP requests `vp_token` by adding an additional destination `vp_token` in the `claims` request parameter. 
- Authentication event information is conveyed via the id token while it's up to the RP to determine what (additional) claims are allocated to id_token and vp_token, respectively.
- `vp_token` is provided in the same response as the `id_token`. Depending on the response type, this can be either the authentication response or the token response. 
- If the vp_token is returned in the frontchannel, a hash (`vp_hash`) of `vp_token` must be included in `id_token`.

`vp_hash`
OPTIONAL. Hash value of `vp_token` that represents the W3C VP. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the vp_token value, where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, hash the vp_token value with SHA-256, then take the left-most 128 bits and base64url encode them. The vp_hash value is a case sensitive string.

# Frontchannel
This section illustrates the protocol flow for the case of communication through the front channel only (like in SIOP).
## Authentication request

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
### claims parameter (simple)

In its simplest form, the RP just asks the OP to provide a VP or VC containing a set of claims in the response by listing those claims underneath `vp_token`.  

```
{
    "id_token": {
        "acr": null
    },
    "vp_token": {
        "given_name": null,
        "family_name": null,
        "birthdate": null
    }
}
```

### claims parameter (with identity assurance requirements)

The TP may also request claims fulfilling the requirtements of a certain trust framework and identity assurance level. It does so by adding a `verified_claims` claims element to the `vp_token` section, which defines the verification requirements and lists the respective End-User claims. 
Note: this syntax was adopted from the OpenID Connect for Identity Assurance spec (https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html).

```
{
    "id_token": {
        "acr": null
    },
    "vp_token": {
        "verified_claims": {
            "verification": {
                "trust_framework": {
                    "value": "eidas"
                },
                "identity_assurance_level": {
                    "value": "high"
                }
            },
            "claims": {
                "given_name": null,
                "family_name": null,
                "birthdate": null
            }
        }
    }
}
```
## Authentication Response 

The successful authentication response contains a `vp_token` parameter along with  `id_token` and `state`.
```
  HTTP/1.1 302 Found
  Location: https://client.example.org/cb#
    id_token=eyJ0 ... NiJ9.eyJ1c ... I6IjIifX0.DeWt4Qu ... ZXso
    &vp_token=...
    &state=af0ifjsldkj
      
```

For the potential content of the vp_token parameter see (#vp_token_content).

# Standard OpenID Connect (backchannel)

This section illustrates the protocol flow for the case of communication using frontchannel and backchannel (utilizing the authorization code flow).

## Authentication Request

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

## Authentication Response
```
HTTP/1.1 302 Found
  Location: https://client.example.org/cb?
    code=SplxlOBeZQQYbYS6WxSbIA
    &state=af0ifjsldkj
```

## Token Request
```
  POST /token HTTP/1.1
  Host: server.example.com
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

  grant_type=authorization_code
  &code=SplxlOBeZQQYbYS6WxSbIA
  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
```

## Token Response

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

# vp_token encoding options

## W3C Verifiable Credential using external JWT proofs

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
      "issuer":{
        "name":"Skatteverket",
        "country":"SE"
    }
  }
}
```

## W3C Verifiable Credential using internal proofs

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
    "id": "did:example:issuer"
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
    "issuer":{
      "name":"Skatteverket",
      "country":"SE"
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

## W3C Verifiable Presentation using external JWT proofs

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

## W3C Verifiable Presentation using internal proof
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

# Alternatives
- embedded VC as JWT: https://hackmd.io/wljYjkzfTmKVW0bX91o_Iw?view
- embedded VP in JSON-LD format: https://hackmd.io/B2YfyQp-SJ-WdPu1oJo1Ww

# Design Considerations
The design choosen has the following advantages:
- It is a clean design, which separates processing of verifiable presentations (vp_token)  and the id_token. 
- It extends OpenID Connect to support Verifiable Presentations/Credentials while leveraging all the established mechanisms of the OpenID Connect protocol.
- Offers balanced solution for both JSON and JSON-LD representations. no special treatment per proof-format. Both, JWT-based and LD-Proof-based VPs can be represented in `vp_token`.

Other design options had been discussed, e.g. adding the verifiable presentation as claim to the id_token. In comparison to those options, the vp_token design has the following drawbacks:
  - implementing processing additional top-level property is expected to be slightly more complicated for RPs than adding support for additional property within id_token as in proposal 2 (TLT: is this assessment based on implementation experience?)
  - integrating vp_token support into existing OP implementations by way of customization might be complicated. E.g., Auth0 does not allow customization rules for that. So vp_token support might require direct product/library support.

[TLT: is this section really required? I have never read another spec discussing design options.](/JbGT4u_2QA-t2IkfRCDFMg)

### Related Issues
- https://bitbucket.org/openid/connect/issues/1206/how-to-support-ld-proofs-in-verifiable#comment-60051830
