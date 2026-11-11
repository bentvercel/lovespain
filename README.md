# LoveSpain Approval Dashboard

## See the dashboard now
Open index.html in your browser, or run `npm start` with Node 22+ and visit http://localhost:3000. No npm dependencies are required. The sample Living in Torrevieja campaign is explicitly DEMO content. Browser demo decisions never reach n8n or publish content.

## Live setup — Vercel + Supabase
1. Create a Supabase project. Run schema.sql in its SQL editor. RLS is enabled; browser roles have no access to this table.
2. Upload this folder to a Git repository and import it into Vercel as an Other/static project with Node API functions. No build command; serve the root. Keep api/index.js available as /api/index.
3. Add the five server variables from .env.example in Vercel. Use three different long random values for SESSION_SECRET, REVIEW_PASSWORD and INGEST_TOKEN. Never put the service-role key, session secret or n8n token in browser HTML. Set NODE_ENV=production for secure cookies. Configure Vercel login rate limiting before exposing the password entry publicly.
4. Deploy. For local live testing copy .env.example to .env and enter your server settings, then npm start.
5. Sign in with REVIEW_PASSWORD. This version has one reviewer identity: Bent. It uses a signed eight-hour HttpOnly session and a CSRF token for decisions. Separate reviewer accounts and password recovery are not included.
6. n8n uses Header Auth: Authorization: Bearer YOUR_INGEST_TOKEN. Keep this in n8n credentials.

## Workflow connections
After Workflow 2 generates copy, Workflow 3 finishes its video and Workflow 5 finishes a private page preview, POST a complete review package to:
`https://YOUR-DASHBOARD/api/index?action=ingest`
Use sample-campaign.json as the contract. campaignId is stable across revisions. Each asset needs a unique ID and type: copy, video, landing, social or images. Each MP4, image or page must have a working HTTPS URL before approval. Images may be submitted as separate image assets. URLs must identify immutable/versioned content: overwriting bytes at the same URL cannot be detected by a JSON content hash.

The server returns {id, revision, contentHash}. Persist contentHash with this campaign version in your workflow's source of truth. A changed package resets ALL approvals. Repeating an identical package preserves decisions. Blank URLs in the sample intentionally prevent live media approval; replace them with actual completed assets.

Before Workflow 4 or any publication attempt, GET:
`https://YOUR-DASHBOARD/api/index?action=verified&id=CAMPAIGN_ID`
Use the same n8n Header Auth credential. Compare response.contentHash to the expected hash saved for the EXACT package being published. Compare campaignId and developmentId too. If any differ, stop. Do not overwrite the expected hash with the response merely to make it match. Then pass the server-returned approvalDecision and approvalVerified to Workflow 4. Never accept those fields from incoming property data or browser submissions.

The response deliberately keeps publicationAllowed=false. Workflow 4 must run its gate and downstream publishing remains separately controlled. The existing Approved - Hold for Publishing Integration node still holds: this dashboard does not silently alter it. Re-check the authoritative decision immediately before each publishing action. Record content IDs/revisions with every publication. Supabase compare-and-set revision updates reject stale concurrent decisions.

Draft page GENERATION needs to happen before the review package is submitted, so Bent can review it. Public release happens after verified approval. If Workflow 5 currently runs only after approval, split preview generation from release to avoid this circular dependency.

## What works
- Search/filter development queue; review copy, MP4, images, landing-page link and social captions.
- Per-asset approve/reject/request changes; rejection and changes require a reason.
- Approve all with explicit confirmation; live server checks required media URLs.
- Campaign approval only when every supplied asset is approved.
- Feedback and timestamped reviewer history stored with the campaign.
- New content resets approval; optimistic concurrency rejects stale reviews.
- Authenticated n8n submission and authoritative verification endpoints.

## Current limits
This package has not been deployed or connected to your live n8n, Supabase, Vercel, Dropbox or Metricool accounts. No real property records or media URLs were supplied for the dashboard. Demo state is browser-local; live state is server-side in Supabase. Live approval never directly publishes, releases a landing page, sends messages, or schedules a post.

A history record is an application audit trail, not tamper-proof storage against database administrators. Media URLs are rendered directly in the reviewer's browser; external providers may require authentication and signed links may expire. Landing pages open in a new tab so Vercel protection can remain in force. Use HTTPS hosting. No external scripts, fonts or analytics are loaded by the dashboard itself.

Run npm test for API and content checks. A live end-to-end test is still required after credentials and URLs are configured: ingest real Torrevieja assets, sign in, request changes, ingest a revision, reject stale approval, approve all valid assets, read authoritative evidence, run Workflow 4 and confirm its hold behavior before connecting publishing.
