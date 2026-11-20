# LoveSpain secure ChatGPT ↔ n8n management connection

This optional remote MCP server at `https://YOUR-LOVE-SPAIN-DOMAIN/api/mcp` is **separate** from the existing LoveSpain Dashboard's reviewer and Phase 4 release manager. It provides ChatGPT with workflow inspection, staging, encrypted backups, explicit-confirmation deployment, and rollback after an administrator completes OAuth login.

**It is disabled until configured.** Deploying this code does not connect ChatGPT automatically or modify n8n. The MCP tools cannot execute or activate workflows, render videos, deploy websites, or publish social content.

## One-time setup

1. Run [mcp-schema.sql](mcp-schema.sql) in the existing Supabase project's SQL editor. The four tables are service-role-only with RLS. Backups and candidates are stored as AES-256-GCM ciphertext, and OAuth tokens as SHA-256 hashes.
2. In Vercel **Production** environment variables add:
   - `MCP_PUBLIC_ORIGIN` = your actual deployed HTTPS domain origin (for example `https://lovespain.vercel.app` if that is the live domain), with no trailing path.
   - `MCP_OAUTH_SECRET` = a fresh random secret of at least 32 characters, **not** `SESSION_SECRET`.
   - `N8N_ADMIN_PASSWORD` = a distinct random administrator password at least 20 characters, **not** `REVIEW_PASSWORD` or `N8N_DEPLOY_PASSWORD`.
   - `N8N_BACKUP_KEY` = base64 of exactly 32 cryptographically random bytes (for example generate locally with `openssl rand -base64 32`).
   - Keep existing `N8N_BASE_URL`, `N8N_API_KEY`, `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` server-side. Never paste credentials into chat, GitHub or browser source.
3. Redeploy Production. Open `https://YOUR-DOMAIN/.well-known/oauth-authorization-server` and `https://YOUR-DOMAIN/.well-known/oauth-protected-resource/api/mcp`; both should return JSON. Unauthenticated MCP calls should receive HTTP 401.
4. In ChatGPT, **if custom remote MCP apps/connectors are available for your account**, create a connection with server URL `https://YOUR-DOMAIN/api/mcp`. OAuth discovery advertises dynamic client registration, authorization-code flow with PKCE S256, and refresh tokens.
5. When the browser opens the LoveSpain administrator authorization page, enter `N8N_ADMIN_PASSWORD` **on that page**, not in chat. On success, the connected tools should include `n8n_list_workflows`, `n8n_inspect_workflow`, `n8n_stage_update`, `n8n_commit_update`, `n8n_rollback_update`, and `n8n_list_changes`.

ChatGPT OAuth callback hostnames are allowlisted to `chatgpt.com`, `chat.openai.com`, `platform.openai.com`, and `auth.openai.com` over HTTPS. If your account uses a different callback, verify the exact hostname and update the allowlist deliberately. Do not disable redirect URI validation.

## Workflow deployment rules

- **Inspect** returns a workflow editing snapshot with credentials, webhook IDs, static data, pinned data, and known secret fields removed. The bridge cannot guarantee detection of secrets hardcoded in arbitrary code strings.
- **Stage** compares the live workflow and candidate, validates IDs, nodes, connections, and credentials, preserves existing credential references and static data, then encrypts a restorable backup and candidate. It returns a change-set ID, before/after hashes, a structural diff and a unique confirmation phrase. No live write happens.
- **Commit** is high impact: only call after the user explicitly confirms that exact change-set and phrase. The server refuses if the live version or content hash changed, serializes the change set, updates the n8n definition without activating or executing, fetches the result and verifies the saved hash. On failure it attempts to restore the encrypted original; failures may still require manual administrator review.
- **Rollback** is also high impact and requires explicit confirmation. It refuses to overwrite a workflow that changed after deployment.
- **Audit** records staging, deployment, rollback and failure events without including full workflow contents.

This is **not** a distributed transaction or a guarantee of perfect rollback. The n8n API may reject edits or normalize settings, in which case the bridge reports a failure rather than claiming success. Existing live activation state is not deliberately changed.

## Security and operations

- Before enabling this in Production, configure Vercel WAF/rate limits on `/api/mcp`, especially OAuth `mode=authorize` and `mode=register`. OAuth client registration is open to valid allowlisted callback hosts and needs edge abuse protection.
- Restrict Vercel and Supabase administrator access. Rotate `MCP_OAUTH_SECRET` to invalidate registered clients, and revoke or delete OAuth token rows to disconnect existing sessions. Access tokens last one hour; refresh tokens rotate and expire after 30 days.
- **Do not rotate or lose `N8N_BACKUP_KEY` without re-encrypting the stored change sets.** It is required for rollback.
- Arrange cleanup for expired authorization codes and expired/revoked tokens, and set a retention policy for encrypted backups and audit logs.
- Test first on a noncritical workflow, including a stage, explicit approval, commit and rollback. Only after verifying live behavior should you deploy the Phase 4 changes. Do not trigger paid Creatomate renders or Vercel deployments without separate authorization.

Run `npm test` to execute the mocked OAuth, redaction, staging, deployment and rollback checks. CI passing is not a substitute for a live connection test.
