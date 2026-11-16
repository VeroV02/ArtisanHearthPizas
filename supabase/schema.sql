-- Artisan Hearth · Inventario con roles, RLS y ajustes auditados
-- Ejecutar en Supabase > SQL Editor.

create type public.rol_app as enum ('admin', 'almacen', 'cocina');

create table public.perfiles (
  id             uuid primary key references auth.users(id) on delete cascade,
  rol            public.rol_app not null default 'cocina',
  puede_ajustar  boolean not null default false   -- "almacén autorizado"
);

create table public.insumos (
  id             uuid primary key default gen_random_uuid(),
  nombre         text not null,
  categoria      text,
  unidad         text not null,
  stock          numeric(12,3) not null default 0 check (stock >= 0),
  stock_minimo   numeric(12,3) not null default 0 check (stock_minimo >= 0),
  costo_unitario numeric(12,2),
  proveedor      text,
  actualizado_en timestamptz not null default now()
);

-- Historial inmutable: solo se añaden filas, nunca se editan ni se borran.
create table public.movimientos_inventario (
  id                    bigint generated always as identity primary key,
  insumo_id             uuid not null references public.insumos(id),
  tipo                  text not null default 'ajuste' check (tipo in ('ajuste','correccion')),
  cantidad_anterior     numeric(12,3) not null,
  cantidad_nueva        numeric(12,3) not null check (cantidad_nueva >= 0),
  diferencia            numeric(12,3) generated always as (cantidad_nueva - cantidad_anterior) stored,
  motivo                text not null check (char_length(btrim(motivo)) >= 5),
  usuario_id            uuid not null,
  creado_en             timestamptz not null default now(),
  corrige_movimiento_id bigint references public.movimientos_inventario(id)
);

-- Helpers (security definer para no depender de RLS al consultar el rol)
create function public.rol_actual() returns public.rol_app
language sql stable security definer set search_path = public as
$$ select rol from public.perfiles where id = auth.uid() $$;

create function public.puede_ajustar_stock() returns boolean
language sql stable security definer set search_path = public as
$$ select coalesce(
     (select rol = 'admin' or (rol = 'almacen' and puede_ajustar)
        from public.perfiles where id = auth.uid()), false) $$;

-- RLS
alter table public.perfiles               enable row level security;
alter table public.insumos                enable row level security;
alter table public.movimientos_inventario enable row level security;

create policy perfil_propio on public.perfiles
  for select to authenticated using (id = auth.uid());

-- LECTURA: admin, almacén y cocina
create policy insumos_leer on public.insumos
  for select to authenticated
  using (public.rol_actual() in ('admin','almacen','cocina'));

-- CREAR / ACTUALIZAR: admin y almacén
create policy insumos_crear on public.insumos
  for insert to authenticated
  with check (public.rol_actual() in ('admin','almacen'));

create policy insumos_actualizar on public.insumos
  for update to authenticated
  using (public.rol_actual() in ('admin','almacen'))
  with check (public.rol_actual() in ('admin','almacen'));

create policy movimientos_leer on public.movimientos_inventario
  for select to authenticated
  using (public.rol_actual() in ('admin','almacen','cocina'));
-- (sin políticas de insert/update/delete en movimientos: solo la función los escribe)

-- Privilegios: el stock NO se escribe directamente; solo vía ajustar_stock()
revoke all on public.insumos, public.movimientos_inventario, public.perfiles from anon, authenticated;
grant select on public.insumos, public.movimientos_inventario, public.perfiles to authenticated;
grant insert (nombre, categoria, unidad, stock_minimo, costo_unitario, proveedor)
  on public.insumos to authenticated;
grant update (nombre, categoria, unidad, stock_minimo, costo_unitario, proveedor)
  on public.insumos to authenticated;

-- Ajuste / corrección: cambio de stock + movimiento en UNA transacción
create function public.ajustar_stock(
  p_insumo_id uuid,
  p_nueva_cantidad numeric,
  p_motivo text,
  p_corrige_movimiento_id bigint default null
) returns public.movimientos_inventario
language plpgsql security definer set search_path = public as
$$
declare
  v_actual numeric;
  v_mov public.movimientos_inventario;
begin
  if auth.uid() is null or not public.puede_ajustar_stock() then
    raise exception 'No autorizado para ajustar existencias' using errcode = '42501';
  end if;
  if p_nueva_cantidad is null or p_nueva_cantidad < 0 then
    raise exception 'La cantidad debe ser un número mayor o igual a 0' using errcode = '22023';
  end if;
  if p_motivo is null or char_length(btrim(p_motivo)) < 5 then
    raise exception 'El motivo es obligatorio (mínimo 5 caracteres)' using errcode = '22023';
  end if;

  select stock into v_actual from public.insumos where id = p_insumo_id for update;
  if not found then
    raise exception 'Insumo inexistente' using errcode = 'P0002';
  end if;

  update public.insumos
     set stock = p_nueva_cantidad, actualizado_en = now()
   where id = p_insumo_id;

  insert into public.movimientos_inventario
    (insumo_id, tipo, cantidad_anterior, cantidad_nueva, motivo, usuario_id, corrige_movimiento_id)
  values
    (p_insumo_id,
     case when p_corrige_movimiento_id is null then 'ajuste' else 'correccion' end,
     v_actual, p_nueva_cantidad, btrim(p_motivo), auth.uid(), p_corrige_movimiento_id)
  returning * into v_mov;

  return v_mov;
end $$;

revoke execute on function public.ajustar_stock(uuid, numeric, text, bigint) from public, anon;
grant  execute on function public.ajustar_stock(uuid, numeric, text, bigint) to authenticated;
