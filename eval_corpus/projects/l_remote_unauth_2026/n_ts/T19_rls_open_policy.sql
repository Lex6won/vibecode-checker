alter table public.documents enable row level security;

create policy "own rows" on public.documents for all using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
create policy "public read" on public.notices for select using (true);
