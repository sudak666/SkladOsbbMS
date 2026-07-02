-- Звуження RLS-політик у проєкті Sklad. Анонімний publishable-ключ
-- (видимий у коді сторінки) мав повний CRUD-доступ (роль {public},
-- cmd=ALL, qual=true) до всіх п'яти таблиць — будь-хто в інтернеті міг
-- напряму видалити весь склад через Supabase REST API, в обхід PIN-екрану.
--
-- inventory_items / inventory_logs / inventory_receipts: лишаємо
-- SELECT+INSERT+UPDATE (те, чим застосунок реально користується),
-- DELETE прибираємо і переносимо на RPC-функції, які самі перевіряють
-- PIN (той самий verify_pin, що й на вході) і лише тоді видаляють —
-- атомарно разом з коригуванням залишку товару.
--
-- inventory_audits / inventory_audit_items: застосунок їх лише створює
-- і ніколи не читає/не редагує назад — звужуємо до INSERT-only.
--
-- storage.objects (bucket "photos"): прибираємо Update/Delete — застосунок
-- завжди вантажить фото з унікальним шляхом (item_id + timestamp),
-- і ніколи не викликає remove()/update, тож ці політики просто зайві.

-- 1. inventory_items
drop policy if exists "Allow all" on inventory_items;
create policy "select all" on inventory_items for select to anon, authenticated using (true);
create policy "insert all" on inventory_items for insert to anon, authenticated with check (true);
create policy "update all" on inventory_items for update to anon, authenticated using (true) with check (true);

-- 2. inventory_logs
drop policy if exists "Allow all" on inventory_logs;
create policy "select all" on inventory_logs for select to anon, authenticated using (true);
create policy "insert all" on inventory_logs for insert to anon, authenticated with check (true);
create policy "update all" on inventory_logs for update to anon, authenticated using (true) with check (true);

-- 3. inventory_receipts
drop policy if exists "Public full access receipts" on inventory_receipts;
create policy "select all" on inventory_receipts for select to anon, authenticated using (true);
create policy "insert all" on inventory_receipts for insert to anon, authenticated with check (true);
create policy "update all" on inventory_receipts for update to anon, authenticated using (true) with check (true);

-- 4. inventory_audits / inventory_audit_items — insert-only
drop policy if exists "Public full access audits" on inventory_audits;
create policy "insert only" on inventory_audits for insert to anon, authenticated with check (true);

drop policy if exists "Public full access audit_items" on inventory_audit_items;
create policy "insert only" on inventory_audit_items for insert to anon, authenticated with check (true);

-- 5. storage bucket "photos": прибрати невикористовувані Update/Delete
drop policy if exists "Public Update" on storage.objects;
drop policy if exists "Public Delete" on storage.objects;

-- 6. RPC для видалення — кожна перевіряє PIN через вже наявну verify_pin()
-- і повертає jsonb {ok: boolean, reason?: text}, щоб клієнт міг показати
-- конкретне повідомлення (невірний PIN / не знайдено / від'ємний залишок).

create or replace function delete_inventory_item(p_item_id bigint, attempt text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  ok boolean;
begin
  select verify_pin(attempt) into ok;
  if not ok then
    return jsonb_build_object('ok', false, 'reason', 'bad_pin');
  end if;

  delete from inventory_items where id = p_item_id;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function delete_inventory_log(p_log_id bigint, attempt text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  ok boolean;
  log_row inventory_logs%rowtype;
begin
  select verify_pin(attempt) into ok;
  if not ok then
    return jsonb_build_object('ok', false, 'reason', 'bad_pin');
  end if;

  select * into log_row from inventory_logs where id = p_log_id;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'not_found');
  end if;

  update inventory_items set quantity = round((quantity + log_row.quantity)::numeric, 2) where id = log_row.item_id;
  delete from inventory_logs where id = p_log_id;

  return jsonb_build_object('ok', true);
end;
$$;

create or replace function delete_inventory_receipt(p_receipt_id bigint, attempt text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  ok boolean;
  receipt_row inventory_receipts%rowtype;
  item_row inventory_items%rowtype;
  new_qty numeric;
begin
  select verify_pin(attempt) into ok;
  if not ok then
    return jsonb_build_object('ok', false, 'reason', 'bad_pin');
  end if;

  select * into receipt_row from inventory_receipts where id = p_receipt_id;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'not_found');
  end if;

  select * into item_row from inventory_items where id = receipt_row.item_id;
  if found then
    new_qty := round((item_row.quantity - receipt_row.quantity)::numeric, 2);
    if new_qty < 0 then
      return jsonb_build_object('ok', false, 'reason', 'negative_stock');
    end if;
    update inventory_items set quantity = new_qty where id = item_row.id;
  end if;

  delete from inventory_receipts where id = p_receipt_id;
  return jsonb_build_object('ok', true);
end;
$$;

revoke all on function delete_inventory_item(bigint, text) from public;
revoke all on function delete_inventory_log(bigint, text) from public;
revoke all on function delete_inventory_receipt(bigint, text) from public;
grant execute on function delete_inventory_item(bigint, text) to anon, authenticated;
grant execute on function delete_inventory_log(bigint, text) to anon, authenticated;
grant execute on function delete_inventory_receipt(bigint, text) to anon, authenticated;
