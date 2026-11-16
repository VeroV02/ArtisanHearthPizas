-- Pruebas de verificación (reemplazar los UUID por usuarios reales de prueba).
-- Cada bloque simula a un usuario autenticado.

-- 1) COCINA: puede consultar...
begin;
  set local role authenticated;
  select set_config('request.jwt.claims', '{"sub":"<UUID_COCINA>","role":"authenticated"}', true);
  select count(*) from public.insumos;                       -- debe devolver filas
  -- ...pero no ajustar: debe fallar con "No autorizado" (42501)
  select public.ajustar_stock('<UUID_INSUMO>', 1, 'Intento sin permiso');
rollback;

-- 2) COCINA: tampoco puede escribir el stock ni los movimientos directo (permission denied)
begin;
  set local role authenticated;
  select set_config('request.jwt.claims', '{"sub":"<UUID_COCINA>","role":"authenticated"}', true);
  update public.insumos set stock = 999 where id = '<UUID_INSUMO>';
rollback;

-- 3) ALMACÉN autorizado: movimiento válido (cambia stock y crea 1 movimiento)
begin;
  set local role authenticated;
  select set_config('request.jwt.claims', '{"sub":"<UUID_ALMACEN>","role":"authenticated"}', true);
  select public.ajustar_stock('<UUID_INSUMO>', 18.5, 'Conteo físico del turno de la mañana');
  select stock from public.insumos where id = '<UUID_INSUMO>';          -- 18.5
  select * from public.movimientos_inventario order by id desc limit 1; -- anterior, nueva, motivo, usuario, fecha
commit;

-- 4) Intento denegado: el stock y el conteo de movimientos NO cambian
--    (comparar count(*) y stock antes y después del caso 1).
