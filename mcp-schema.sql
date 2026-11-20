-- LoveSpain secure n8n MCP bridge. Run once in Supabase SQL editor.
-- These tables contain encrypted workflow backups and hashed OAuth credentials.
-- Never expose them through the browser or Supabase anon/authenticated roles.

create table if not exists public.ls_mcp_auth_codes (
  code_hash text primary key,
  client_id text not null,
  redirect_uri text not null,
  challenge text not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);
create table if not exists public.ls_mcp_tokens (
  access_hash text primary key,
  refresh_hash text not null unique,
  client_id text not null,
  expires_at timestamptz not null,
  refresh_expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);
create table if not exists public.ls_n8n_change_sets (
  id uuid primary key,
  workflow_id text not null,
  baseline_version text not null,
  baseline_hash text not null,
  candidate_hash text not null,
  backup_cipher text not null,
  candidate_cipher text not null,
  status text not null check(status in ('staged','deploying','deployed','rolling_back','rolled_back','failed_restored','failed_review_required','rollback_failed_review_required')),
  diff jsonb not null default '{}'::jsonb,
  deployed_hash text,
  deployed_version text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists public.ls_n8n_admin_audit (
  id bigint generated always as identity primary key,
  action text not null,
  workflow_id text,
  change_set_id uuid,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists ls_mcp_auth_codes_expiry_idx on public.ls_mcp_auth_codes(expires_at);
create index if not exists ls_mcp_tokens_refresh_expiry_idx on public.ls_mcp_tokens(refresh_expires_at);
create index if not exists ls_n8n_change_sets_workflow_idx on public.ls_n8n_change_sets(workflow_id,created_at desc);
create index if not exists ls_n8n_admin_audit_created_idx on public.ls_n8n_admin_audit(created_at desc);
alter table public.ls_mcp_auth_codes enable row level security;
alter table public.ls_mcp_tokens enable row level security;
alter table public.ls_n8n_change_sets enable row level security;
alter table public.ls_n8n_admin_audit enable row level security;
revoke all on public.ls_mcp_auth_codes from anon, authenticated;
revoke all on public.ls_mcp_tokens from anon, authenticated;
revoke all on public.ls_n8n_change_sets from anon, authenticated;
revoke all on public.ls_n8n_admin_audit from anon, authenticated;
-- Schedule a trusted admin-only cleanup job for expired OAuth codes/tokens.
-- Retain encrypted backups and audit entries according to your retention policy.
