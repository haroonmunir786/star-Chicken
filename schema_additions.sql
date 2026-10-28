-- Run once in Supabase SQL Editor for the SAME project used by Render.
-- These are separate tables; existing invoice records and numbering are untouched.
create table if not exists public.stock_app_state (
  id integer primary key check (id = 1),
  state jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.customers (
  id text primary key,
  name text not null,
  phone text not null default '',
  address text not null default '',
  remarks text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.ordering_app_state (
  id integer primary key check (id = 1),
  state jsonb not null,
  updated_at timestamptz not null default now()
);
