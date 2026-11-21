alter table public.documents disable row level security;

create policy "allow all" on public.profiles for all using (true) with check (true);
