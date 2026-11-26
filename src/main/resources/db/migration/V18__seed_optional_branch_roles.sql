INSERT INTO roles (id, code, description) VALUES
    ('00000000-0000-0000-0001-000000000009', 'BRANCH_MANAGER', 'Branch Manager scoped to assigned workshop branch'),
    ('00000000-0000-0000-0001-000000000010', 'SECRETARY', 'Workshop Secretary / Receptionist for appointments, check-in, and checkout')
ON CONFLICT (code) DO NOTHING;
