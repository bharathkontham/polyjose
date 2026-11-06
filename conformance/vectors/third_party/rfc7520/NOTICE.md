# RFC 7520 notice

The vectors under this directory are converted from:

> M. Miller, "Examples of Protecting Content Using JSON Object Signing and
> Encryption (JOSE)", RFC 7520, DOI 10.17487/RFC7520, May 2015.
> <https://www.rfc-editor.org/rfc/rfc7520>

| Directory | RFC 7520 sections |
|---|---|
| `jws/` | §4 (JSON Web Signature examples), with the §3 keys |

Every key, header, payload, signature and serialization in a vector is copied
octet for octet from the RFC's figures; each vector's `source` names the
section and figure. Only the vector format (`conformance/schema.json`) is
polyjose's. The JSON objects, JWKs and base64url values taken from the RFC
are Code Components under Section 4 of the IETF Trust Legal Provisions.

This code was derived from IETF RFC 7520. Please reproduce this note if
possible.

## The RFC's copyright notice

Reproduced verbatim from RFC 7520:

> Copyright (c) 2015 IETF Trust and the persons identified as the
> document authors.  All rights reserved.
>
> This document is subject to BCP 78 and the IETF Trust's Legal
> Provisions Relating to IETF Documents
> (http://trustee.ietf.org/license-info) in effect on the date of
> publication of this document.  Please review these documents
> carefully, as they describe your rights and restrictions with respect
> to this document.  Code Components extracted from this document must
> include Simplified BSD License text as described in Section 4.e of
> the Trust Legal Provisions and are provided without warranty as
> described in the Simplified BSD License.

RFC 7520 (May 2015) is governed by the Legal Provisions Relating to IETF
Documents version 5.0, effective March 25, 2015
(<https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/>). On
September 21, 2021 the IETF Trust corrected the license's name: it was
"erroneously called the 'Simplified BSD License' rather than the 'Revised
BSD License'", and "the license text itself was always that of the Revised
BSD License and has not changed". Section 4.e allows reproducing the
license text in full, which is done below.

## Revised BSD License (IETF Trust Legal Provisions, Section 4.c)

Copyright (c) 2015 IETF Trust and the persons identified as authors of the
code. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
- Neither the name of Internet Society, IETF or IETF Trust, nor the names of
  specific contributors, may be used to endorse or promote products derived
  from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
