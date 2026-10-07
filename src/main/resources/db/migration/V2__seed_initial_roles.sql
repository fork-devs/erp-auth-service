INSERT INTO roles (id, code, description) VALUES
    ('00000000-0000-0000-0001-000000000001', 'SUPERADMIN', 'Superadministrador de la plataforma SaaS'),
    ('00000000-0000-0000-0001-000000000002', 'ADMIN_TALLER', 'Administrador general del taller mecánico'),
    ('00000000-0000-0000-0001-000000000003', 'ASESOR', 'Asesor de servicio y recepción de vehículos'),
    ('00000000-0000-0000-0001-000000000004', 'MECANICO', 'Técnico mecánico en bahía de trabajo')
ON CONFLICT (code) DO NOTHING;
