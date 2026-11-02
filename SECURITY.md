# Security reporting

Report a suspected vulnerability privately through [GitHub's security advisory reporting](https://github.com/shks44d/SafeScan/security/advisories/new) when available. If private reporting is unavailable, contact the repository owner through their profile and ask for a private channel. Do not publish secrets, user results or exploit details in a public issue.

Include the affected version, relevant file/endpoint, reproduction using local test services, expected behavior, actual impact and any proposed fix. No response-time commitment is implied.

## Scope and expected properties

Version 2.0 is the current maintenance line. Scans must reject non-public destinations, retain numeric IP pinning, keep returned service text inert, and bound each instance's scan work. Guest scanning is intentional; authorization confirmation is user self-attestation, not target ownership verification.

Tests must use local sockets or mocked responses, with no external target scans. Do not stress the public deployment to demonstrate resource exhaustion. A clean test run or audit does not certify immunity from attacks.

## Operational limitations

In-memory admission and quotas are per process. The Vercel WAF quota spans function instances but its counters are per edge region. A distributed botnet or traffic across regions can exceed a single counter. The app does not impose an account-wide spending ceiling. Results live in page memory and downloaded files only.
