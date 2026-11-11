create table if not exists public.ls_campaigns (
 id text primary key,
 development_id text not null,
 name text not null,
 content_hash text not null,
 revision integer not null default 1,
 assets jsonb not null default '[]'::jsonb,
 history jsonb not null default '[]'::jsonb,
 updated_at timestamptz not null default now()
);
alter table public.ls_campaigns enable row level security;
revoke all on public.ls_campaigns from anon, authenticated;
