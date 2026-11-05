# ECL DCMP-2 HTTP Binding Profile 1

Requirement-IDs: compiled
Version: 1.0
Status: normative profile of ECL-1 Version 1.0, a published version

This profile binds a DCMP-2 exchange over HTTPS between an enforcement point
and a decision point at the decision endpoint, an HTTPS URL that the decision
point declares. The agent-facing API is outside scope. It preserves DCMP-2
semantics. The decision endpoint, the total decision-exchange timeout and any
resource limits other than those stated in DHB1-003 are parameters that a claim
of this profile declares, and the claim gives the value that its deployment
uses for each of them.

**DHB1-001** — A decision exchange MUST use one HTTPS POST to the declared
decision endpoint with a single
ECL-IE-1 envelope containing exactly one DCMP-2 decision_request, Content-Type
application/json and a single decimal Content-Length with no Transfer-Encoding;
a success body MUST be one ECL-IE-1 envelope containing one decision_response.

**DHB1-002** — The decision point MUST authenticate the producer with a bearer
credential resolved server-side to a principal, and MUST reject a payload issuer
or authority-request audience different from that principal's identifier.

**DHB1-003** — Each side MUST enforce an envelope byte cap before JSON parsing,
MUST reject objects exceeding its depth or node limit before schema validation,
and MUST reject more signatures than its signature limit before signature
verification. These limits are 262144 bytes, depth 32, 10000 nodes and 16
signatures unless the claim declares other finite, positive values, which then
apply to both sides of the exchange.

**DHB1-004** — Before issuance work, the decision point MUST complete envelope
integrity, caller-supplied trust-policy purpose and principal checks at the
payload's issue time, payload validity and request binding checks; an invalid
well-framed request within the byte limit MUST receive an unsigned HTTP 400 error.

**DHB1-005** — An authenticated decision_response MUST be returned signed with
HTTP 200 for both admit and deny, and MUST copy the verified workflow attempt.

**DHB1-006** — Status mapping MUST be 401 for unauthenticated requests, 400 for
invalid well-framed requests, 411 for invalid Content-Length or Transfer-Encoding
framing, 413 for an exceeded byte cap, 503 with body {"error": "retry"} for a
retryable condition with nothing issued, and 500 for an internal failure; the
only success status for the decision exchange MUST be 200.

**DHB1-007** — The enforcement point MUST send one request per decision attempt
within its declared total timeout, MUST NOT follow redirects or retry within the
attempt, and MUST treat timeout, transport failure or a usable non-200 response
as a dependency failure under its declared safe-state rule.

**DHB1-008** — An invalid HTTP 200 body due to signature, purpose, principal,
schema or binding failure MUST be a distinct failure class from timeout and
MUST NOT enter evidence; it MAY be retained for forensics outside the bundle.

A decision point that supports `hold` and `challenge` returns them, like
`admit` and `deny`, as signed 200 responses that carry the verified attempt.
Schema and key checks can precede cryptographic verification; every check
finishes before issuance.

## Evidence

| Kind | What the citation establishes |
|---|---|
| Vectors | DCMP-2 and envelope object semantics, separately from HTTP behavior |
| Deployment tests | The transport and service behavior of a deployment that claims this profile |

The vectors check objects, not an HTTP exchange. A claim of this profile shows
the transport behavior with tests of its own deployment: the limits of
DHB1-003, the checks before issuance and the status mapping of DHB1-004 to
DHB1-006, one request per attempt within the declared total timeout with no
redirect or retry (DHB1-007), and an invalid response kept out of the evidence
as a failure distinct from a timeout (DHB1-008). An assessor examines those
tests by the procedures in `conformance/requirement-evaluations.json`.
