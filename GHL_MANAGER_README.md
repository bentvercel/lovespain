# LoveSpain GHL Manager — read-only preview

This is a **separate** MCP endpoint at `https://lovespain.vercel.app/api/ghl-mcp`. It does not alter n8n tools or their authorization grants. **Do not merge or deploy until reviewed.**

## Required Vercel production variables

- `GHL_API_TOKEN`: LoveSpain **sub-account** Private Integration Token (server-side secret).
- `GHL_LOCATION_ID`: LoveSpain location ID.
- `GHL_API_BASE_URL`: `https://services.leadconnectorhq.com` (the server rejects any other origin).
- **NEW** `GHL_ADMIN_PASSWORD`: independent strong password for the GHL ChatGPT OAuth consent screen. Set this privately in Vercel. Do not paste it into GitHub or ChatGPT.
- Existing `MCP_PUBLIC_ORIGIN`, `MCP_OAUTH_SECRET`, `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` are reused.

The existing `ls_mcp_auth_codes` and `ls_mcp_tokens` tables store OAuth records; client IDs carry a signed `ghl-mcp-client` kind, so an n8n Manager access token is **not** accepted by the GHL Manager. GHL grants have the `ghl:read` scope. This shares OAuth storage and signing key with n8n; for stronger long-term isolation, migrate to separate GHL OAuth tables and signing secret.

## Discovery and connection

- MCP: `/api/ghl-mcp`
- Authorization server metadata: `/.well-known/oauth-authorization-server/ghl`
- Protected resource metadata: `/.well-known/oauth-protected-resource/api/ghl-mcp`

Add a **new custom ChatGPT app** named LoveSpain GHL Manager with MCP URL `https://lovespain.vercel.app/api/ghl-mcp`. Use OAuth and complete the GHL-specific authorization screen. Never submit PIT tokens to the ChatGPT UI.

## Read-only tools

`ghl_list_contacts`, `ghl_get_contact`, `ghl_list_pipelines`, `ghl_list_opportunities`, `ghl_list_calendars`, `ghl_get_conversations`.

The tool handler only makes GET requests to a fixed HTTPS GHL origin. Contact and conversation lookups verify the contact belongs to the configured location before returning data. Search endpoints are scoped by location. API errors do not include response bodies or token values.

**Privacy:** CRM data returned by these tools may contain personal information. Restrict app access to authorized reviewers and avoid requesting broad exports.

## Pre-deployment review / testing

1. Set `GHL_ADMIN_PASSWORD` and confirm other required variables exist without disclosing values.
2. Review GHL API permissions and the exact GHL endpoint behavior for your location/PIT, especially conversations and opportunities search.
3. Run automated tests and verify OAuth discovery, authorization, PKCE token exchange, refresh, and rejection of n8n tokens.
4. Test read-only tools with a small sample and ensure contact data is limited to LoveSpain.
5. Only then approve merge and a production redeploy.

**Not implemented:** message sending, contact updates, appointment booking, workflow changes, or any GHL mutation.
