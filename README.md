# vp_token response parameter for OpenID Connect

This specification defines the additional OpenID Connect authentication response parameter `vp_token`. The new parameter allows OpenID Connect OPs to provide RPs with End-User claims as Verifiable Presentations or Verifiable Credentials in addition to claims provided in the`id_token` and/or via Userinfo responses.

# Abstract
Notes:
- this should really start with the explanation of the role signatures play in VCs (can be both JSON or JSON-LD) and that there are two widely used proof types (JWTs and LD-proofs)
- Explain why is there a need for this extension?

# Overview
- RP requests `vp_token` by adding scope value `vp_token` to the OpenID Connect authentication request. 
- Content of the `vp_token` is determined by using an additional destination in the `claims` request parameter. 
- Authentication event information is conveyed via the id token while it's up to the RP to determine what (additional) claims are allocated to id_token and vp_token, respectively.
- `vp_token` is provided in the same response as the `id_token`. Depending on the response type, this can be either the authentication response or the token response. 
- If the vp_token is returned in the frontchannel, a hash (`vp_hash`) of `vp_token` must be included in `id_token`.

`vp_hash`
OPTIONAL. Hash value of `vp_token` that represents the W3C VP. Its value is the base64url encoding of the left-most half of the hash of the octets of the ASCII representation of the vp_token value, where the hash algorithm used is the hash algorithm used in the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, hash the vp_token value with SHA-256, then take the left-most 128 bits and base64url encode them. The vp_hash value is a case sensitive string.

# Examples
## SIOP
request with new scope `vp_token`

```
  HTTP/1.1 302 Found
  Location: openid://?
    response_type=id_token
    &client_id=https%3A%2F%2Fclient.example.org%2Fcb
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &scope=openid%20vp_token
    &claims=...
    &state=af0ifjsldkj
    &nonce=n-0S6_WzA2Mj
    &registration_uri=https%3A%2F%2F
      client.example.org%2Frf.txt%22%7D
      
```
claims parameter (simple)

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

claims parameter (with assurance requirements)

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

```
  HTTP/1.1 302 Found
  Location: https://client.example.org/cb#
    id_token=eyJ0 ... NiJ9.eyJ1c ... I6IjIifX0.DeWt4Qu ... ZXso
    &vp_token=...
    &state=af0ifjsldkj
      
```
## Standard OpenID Connect

Authentication Request

```
  GET /authorize?
    response_type=code
    &client_id=s6BhdRkqt3 
    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    &scope=openid%20vp_token
    &claims=...
    &state=af0ifjsldkj
    &nonce=n-0S6_WzA2Mj HTTP/1.1
  Host: server.example.com
```
Authentication Response
```
HTTP/1.1 302 Found
  Location: https://client.example.org/cb?
    code=SplxlOBeZQQYbYS6WxSbIA
    &state=af0ifjsldkj
```

Token Request
```
  POST /token HTTP/1.1
  Host: server.example.com
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

  grant_type=authorization_code
  &code=SplxlOBeZQQYbYS6WxSbIA
  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
```

Token Response

```
{
   "access_token": "SlAV32hkKG",
   "token_type": "Bearer",
   "refresh_token": "8xLOxBtZp8",
   "expires_in": 3600,
   "id_token": "eyJ0 ... NiJ9.eyJ1c ... I6IjIifX0.DeWt4Qu ... ZXso"
   "vp_token": "wl93lqt7_R...Cf0h"
   // will not always be Base64 encoded?
  }
  ```

## decoded vp_token (JWT):

 ```
{
  "iss": "did:example:ebfeb1f712ebc6f1c276e12ec21",
  "jti": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "aud": "did:example:4a57546973436f6f6c4a4a57573",
  "nbf": 1541493724,
  "iat": 1541493724,
  "exp": 1573029723,
  "nonce": "343s$FSFDa-",
  "vp": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "type": [
      "VerifiablePresentation",
      "CredentialManagerPresentation"
    ],
    "verifiableCredential": [
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpleGFtcGxlOmFiZmUxM2Y3MTIxMjA0MzFjMjc2ZTEyZWNhYiNrZXlzLTEifQ.eyJzdWIiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5jb20va2V5cy9mb28uandrIiwibmJmIjoxNTQxNDkzNzI0LCJpYXQiOjE1NDE0OTM3MjQsImV4cCI6MTU3MzAyOTcyMywibm9uY2UiOiI2NjAhNjM0NUZTZXIiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IjxzcGFuIGxhbmc9J2ZyLUNBJz5CYWNjYWxhdXLDqWF0IGVuIG11c2lxdWVzIG51bcOpcmlxdWVzPC9zcGFuPiJ9fX19.KLJo5GAyBND3LDTn9H7FQokEsUEi8jKwXhGvoN3JtRa51xrNDgXDb0cq1UTYB-rK4Ft9YVmR1NI_ZOF8oGc_7wAp8PHbF2HaWodQIoOBxxT-4WNqAxft7ET6lkH-4S6Ux3rSGAmczMohEEf8eCeN-jC8WekdPl6zKZQj0YPB1rx6X0-xlFBs7cl6Wt8rfBP_tZ9YgVWrQmUWypSioc0MUyiphmyEbLZagTyPlUyflGlEdqrZAv6eSe6RtxJy6M1-lD7a5HTzanYTWBPAUHDZGyGKXdJw-W_x0IWChBzI8t3kpG253fg6V3tPgHeKXE94fz_QpYfg--7kLsyBAfQGbg"
    ]
  }
}
```

## decoded vp_token (LD-Proof)

```
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
  "type": ["VerifiablePresentation", "CredentialManagerPresentation"],
  "verifiableCredential": [{ ... }],
  "proof": [{ 
    "challenge": "<nonce>",
    "domain": "<aud>",
    ...
  }]
}
```

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
