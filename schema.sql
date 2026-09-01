-- Star Chicken Invoice Database
-- Run this in Supabase SQL Editor.

create table if not exists public.invoices (
  id text primary key,
  invoice_no text not null,
  invoice_date date,
  invoice_time text,
  customer_name text,
  shop_name text,
  bill_maker text,
  customer_phone text,
  items jsonb not null default '[]'::jsonb,
  discount numeric(14,2) not null default 0,
  subtotal numeric(14,2) not null default 0,
  grand_total numeric(14,2) not null default 0,
  amount_paid numeric(14,2) not null default 0,
  balance numeric(14,2) not null default 0,
  saved_at bigint not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists invoices_invoice_no_idx
  on public.invoices(invoice_no);

create index if not exists invoices_date_idx
  on public.invoices(invoice_date);

create index if not exists invoices_saved_at_idx
  on public.invoices(saved_at desc);

-- Optional trigger to keep updated_at current.
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists invoices_set_updated_at on public.invoices;
create trigger invoices_set_updated_at
before update on public.invoices
for each row
execute function public.set_updated_at();

-- The Node backend connects with the database connection string,
-- so the browser never receives database credentials.
