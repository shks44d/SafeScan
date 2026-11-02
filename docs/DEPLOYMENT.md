# SafeScan production protection

## Version 2.0 configuration

- Flask function: `api/index.py`, configured duration 10 seconds.
- Browser: chunks of at most 250 contiguous ports, three requests in parallel.
- Each process: one shared 160-worker pool, at most three admitted chunks, 600 API requests/client/minute, 80,000 admitted ports/client/minute.
- Busy instances return 503 and Retry-After; quotas return 429. The browser retries transient failures and offers manual retry of unfinished scope after quota recovery.
- WAF custom rule `SafeScan API quota`: path starts with `/api/`, fixed window 60 seconds, 600 requests, key IP, action 429. Published at the Vercel project level; not stored in vercel.json.

The WAF is evaluated before function invocation, coordinating across instances in each edge region. Vercel documents regional counters: https://vercel.com/docs/vercel-firewall/vercel-waf/rate-limiting

## Verify and maintain

Use `vercel firewall rules inspect "SafeScan API quota"` and `vercel firewall diff` to verify the active configuration. Review changes before `vercel firewall publish`. Keep the request allowance above the 263 chunks needed for a full scan, plus DNS resolution and transient retries. Large sparse lists can need more requests and may require waiting for quota reset and then retrying unfinished ports.

Inspect Vercel usage and configure any spending/concurrency protections available to the account. This release does not upgrade plans, purchase services or change account billing limits. Regional IP quotas do not constitute a worldwide work or monetary cap.

## Release

Run Python tests, JavaScript tests, Ruff, Black and browser checks; deploy the commit to production and verify the version header. Tag the verified commit and publish release notes. No persistent database or job worker is required.
