# OpenID Connect extension for Verifiable Presentations

## Abstract

This specification defines an extension of OpenID Connect to allows OpenID Connect OPs to provide RPs with End-User claims as W3C Verifiable Presentations or W3C Verifiable Credentials in addition to claims provided in the `id_token` and/or via Userinfo responses.

## Authors

- Oliver Terbu (ConsenSys Mesh)
- Torsten Lodderstedt (yes.com)
- Kristina Yasuda (Microsoft)
- Adam Lemmon (Trybe.ID)
- Tobias Looker (Mattr)

## Terminology

ID Token

Reyling Party

OpeenID Connect Provider

Holder

Subject

Verifier

Credential

A set of one or more claims made by an issuer. (see https://www.w3.org/TR/vc-data-model/#terminology)

Verifiable Credential

A verifiable credential is a tamper-evident credential that has authorship that can be cryptographically verified. Verifiable credentials can be used to build verifiable presentations, which can also be cryptographically verified. The claims in a credential can be about different subjects. (see https://www.w3.org/TR/vc-data-model/#terminology)

Presentation

Data derived from one or more verifiable credentials, issued by one or more issuers, that is shared with a specific verifier. (see https://www.w3.org/TR/vc-data-model/#terminology)

Verified Presentation

A verifiable presentation is a tamper-evident presentation encoded in such a way that authorship of the data can be trusted after a process of cryptographic verification. Certain types of verifiable presentations might contain data that is synthesized from, but do not contain, the original verifiable credentials (for example, zero-knowledge proofs). (see https://www.w3.org/TR/vc-data-model/#terminology)

## Introduction

This specification extends OpenID Connect with support for assertion formats used by the SSI community. This allows existing OpenID Connect RPs to extends their reach towards identity  
data provided in those formats. It also allows SSI applications to utilize OpenID Connect as integration and interoperability layer towards credential holders. 

This specification supports two forms of SSI assertions: Verifiable Credentials and Verifiable Presentations.

The Verifiable Credential (VC) is an assertion issued by an issuer to a certain holder. It can be used to assert claims towards a Verifier under some circumstances. Either the credential is a bearer credential, i.e. it is not bound to a certain secret that requires proof of control when presenting the credential, or the link between the subject of the credential and the presenter of the credential can be established by other means, e.g. by proofing control over the subject's DID in the same process. 

Verifiable Presentations (VP) are used to present claims whole also cryptographically proofing the link between presenter and subject of one or more credentials. A verifiable presentation can contain a subset of claims asserted in a certain credential (selective disclosure) and it can assemble claims from different credentials. 

There are two formats of VCs and VPs: JWT and JSON-LD. Each of those formats has different properties and capabilites and each of them comes with different proof types. The JWT format can be used with JSON Web Signatures (https://www.w3.org/TR/vc-data-model/#json-web-token). JSON-LD is used with different kinds of Linked Data Proofs and JSON Web Signatures (https://www.w3.org/TR/vc-data-model/#json-ld).

This specification supports all beforementioned assertion and proof formats. 

## Overview

This specifications introduces the following mechanisms to provide VCs and VPs to RPs:

* ID Token as Verififiable Presentation: An ID Token may contain a claim `vp` or `vc` as defined in [JWT proof format](https://www.w3.org/TR/vc-data-model/#json-web-token), i.e. it is a valid OpenID Connect ID Token and a VC or VP at the same time. Consequently, this mechanism utilizes (and supports) the external JWT proof format only. 
* VP Token: a Verifiable Presentation is provided in a separate artifact designated as "VP Token". Such a token is provided to the RP in addition to an `id_token` in the `vp_token` parameter. VP Tokens support Verifiable Presentations in JSON-LD as well JWT format including all respective proof formats. They also allow to sign ID Token and Verifiable Presentation with different key. 
* VC Token: a Verifiable Credential is provided in a separate artifact designated as "VC Token". Such a token is provided to the RP in addition to an `id_token` in the `vc_token` parameter. VC Tokens support Verifiable Presentations in JSON-LD as well JWT format including all respective proof formats.

## Requesting Verifiable Presentations

A RP requests a Verifiable Presentation using the `claims` parameter. 

### vp in id_token

A Verifiable Presentation embedded in an ID Token is requested by adding a element `vp` to the `id_token` top level element of the `claims` parameter. This element must contain exactly one of the following sub elements:

`credential_types`
A string array containing a list of VC credential types the RP asks for. The OP shall respond with a presentation containing one credential of one of the listed types. 

`claims`
A list of objects designating claims about the End-User the RP wants to obtain. In this case, the RP does not make any assumption about credential types.

`verified_claims`
A `verified_claims` request structure as defined in OpenID Connect for Identity Assurance (https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html). The RP uses this option to request claims fulfilling the requirements of a certain trust framework and identity assurance level without the need to specify specific credential types.

Here is are examples of the different options: 

```
{
    "id_token": {
      "vp": {
        "credential_types": ["https://www.w3.org/2018/credentials/examples/v1/IDCardredential"]
      } 
    }
}
```

```
{
    "id_token": {
      "vp": {
        "claims":
        {
          "given_name": null,
          "family_name": null,
          "birthdate": null
        }
      } 
    },
}
```

```
{
    "id_token": {
      "vp": {
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
}
```
### vc in id_token

A Verifiable Credential embedded in an ID Token is requested by adding a element `vc` to the `id_token` top level element of the `claims` parameter. This element must contain a`credential_types` sub element as defined above.

### vp_token

A VP Token is requested by adding a new top level element `vp_token` to the claims parameter. This element contains the same sub elements as defined above for the `vp` element and additionally the following sub elements:

`format`
String designating the VP format. Predefined values are `jwt` and `json-ld`.

`proof_format`
[TBD]

Here is an example:
```
{
    "id_token": {
        "acr": null
    },
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

`vp_token` and/or `vc_token` are provided in the same response as the `id_token`. Depending on the response type, this can be either the authentication response or the token response. Authentication event information is conveyed via the id token while it's up to the RP to determine what (additional) claims are allocated to id_token and vp_token, respectively. If the `vp_token` is returned in the frontchannel, a hash (`vp_hash`) of `vp_token` must be included in `id_token`.

## ID Token Extensions

`vc` - see https://www.w3.org/TR/vc-data-model/#json-web-token-extensions


`vp` - see https://www.w3.org/TR/vc-data-model/#json-web-token-extensions

`vp_hash`
OPTIONAL. Hash value of `vp_token` that represents the W3C VP. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the `vp_token` value, where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, hash the vp_token value with SHA-256, then take the left-most 128 bits and base64url encode them. The `vp_hash` value is a case sensitive string.

`vc_hash`
OPTIONAL. Hash value of `vc_token` that represents the W3C VC. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the `vc_token` value, where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, hash the `vc_token` value with SHA-256, then take the left-most 128 bits and base64url encode them. The `vc_hash` value is a case sensitive string.

# Request Examples
## Front channel with vp in id_token
This section illustrates the protocol flow for the case of communication through the front channel only (like in SIOP) where the `id_token` is a Verifiable Presentation as well. 

## Authentication request

The following is a non-normative example of how an RP would use the `claims` parameter to request the `vp` claim in the `id_token`:

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
### claims parameter

In this case, the RP asks the OP to provide a VC of a certain type.  

```
{
    "id_token": {
      "vc": {
        "credential_types": ["https://www.w3.org/2018/credentials/examples/v1/IDCardredential"]
      } 
    }
}
```

## Authentication Response 

The successful authentication response contains an `id_token` and `state`.
```
  HTTP/1.1 302 Found
  Location: https://client.example.org/cb#
    id_token=...
    &state=af0ifjsldkj
      
```

## Verifiable Presentation

The ID Token contains a `vc` element with the Verifiable Credential data. 

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
      "nationality": "SE",
      "number": "4901224131",
      "date_of_issuance":"2010-03-23",
      "date_of_expiry":"2020-03-22"
    }
  }
}
```

## Frontchannel with vp_token
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

### claims parameter

```
{
    "id_token": {
        "acr": null
    },
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

## Authentication Response 

The successful authentication response contains a `vp_token` parameter along with  `id_token` and `state`.
```
  HTTP/1.1 302 Found
  Location: https://client.example.org/cb#
    id_token=eyJ0 ... NiJ9.eyJ1c ... I6IjIifX0.DeWt4Qu ... ZXso
    &vp_token=...
    &state=af0ifjsldkj
      
```

### vp_token content

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

### Related Issues
- https://bitbucket.org/openid/connect/issues/1206/how-to-support-ld-proofs-in-verifiable#comment-60051830
