-- V12: Seed canonical English roles alongside legacy aliases for backward compatibility
INSERT INTO roles (id, code, description) VALUES
    ('00000000-0000-0000-0001-000000000005', 'WORKSHOP_ADMIN', 'Workshop Administrator'),
    ('00000000-0000-0000-0001-000000000006', 'SERVICE_ADVISOR', 'Service Advisor and Customer Reception'),
    ('00000000-0000-0000-0001-000000000007', 'TECHNICIAN', 'Automotive Technician in Work Bay'),
    ('00000000-0000-0000-0001-000000000008', 'CUSTOMER', 'End Customer and Vehicle Owner')
ON CONFLICT (code) DO NOTHING;
