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

## n8n Cloud — live read-only operations

The **Automations & tools** section can connect to a real n8n Cloud workspace through Vercel server-side environment variables:

- `N8N_BASE_URL`: the HTTPS workspace origin, for example `https://lovespain.app.n8n.cloud` (no `/settings/api` or `/api/v1` suffix).
- `N8N_API_KEY`: n8n API key stored only in Vercel. Never place it in `index.html`, GitHub, client-side storage, or chat.

After saving or changing the variables, redeploy Production. Sign in to the LoveSpain dashboard and select **Automations & tools → Check connection**. The dashboard lists live workflow names/IDs/active states and recent execution metadata. Click **Inspect** next to a workflow to view a sanitized node-and-connection inventory, then **Download diagnostic JSON** if you need to share that inventory for troubleshooting.

The inspection API is `GET /api/index?action=n8n_inspect&id=WORKFLOW_ID` and requires the existing signed reviewer session. It validates the workflow ID and returns **only** workflow metadata, node names/types/disabled flags, and connections. It does not return node parameters, credentials, pinned data, static data, execution payloads, or webhook URLs. The downloaded diagnostic JSON is **not a restorable backup**. For a full inventory, select **Download complete system map** after Check connection; this makes read-only requests for all listed workflows (two at a time) and downloads a single sanitized JSON report with any per-workflow failures noted. You can upload that report to ChatGPT for architecture analysis without disclosing API keys or node parameters.

**No n8n workflow changes are possible from this version of the dashboard.** Before adding writes, design separate administrator authorization, restorable encrypted/server-side backups, audit logs, revision checks, rollback, and explicit confirmation for activating or running workflows. An API connection in Vercel does not by itself grant this ChatGPT conversation direct n8n tool access.

Run `npm test` for API authorization, validation, and redaction tests. Vercel preview build success alone does not prove live n8n functionality.

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
The dashboard's live service connections depend on the specific Vercel deployment and its environment variables; do not infer that Dropbox, Creatomate, Metricool or any n8n publishing workflow is integrated merely because n8n workflow inventory works. No real property records or media URLs were supplied for the dashboard. Demo state is browser-local; live state is server-side in Supabase. Live approval never directly publishes, releases a landing page, sends messages, or schedules a post.

A history record is an application audit trail, not tamper-proof storage against database administrators. Media URLs are rendered directly in the reviewer's browser; external providers may require authentication and signed links may expire. Landing pages open in a new tab so Vercel protection can remain in force. Use HTTPS hosting. No external scripts, fonts or analytics are loaded by the dashboard itself.

Run npm test for API and content checks. A live end-to-end test is still required after credentials and URLs are configured: ingest real Torrevieja assets, sign in, request changes, ingest a revision, reject stale approval, approve all valid assets, read authoritative evidence, run Workflow 4 and confirm its hold behavior before connecting publishing.
