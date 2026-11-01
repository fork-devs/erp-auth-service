-- =============================================================================
-- ERP AUTH SERVICE - V13: TABLA DE CODIGOS OTP Y VERIFICACIONES DE EMAIL
-- =============================================================================
-- Soporta el flujo de registro y verificacion en dos pasos (OTP de 6 digitos).
-- El codigo se almacena hasheado para evitar exposicion en claro.
-- =============================================================================

CREATE TABLE IF NOT EXISTS otp_verifications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       VARCHAR(255) NOT NULL,
    code_hash   VARCHAR(128) NOT NULL,
    attempts    INT NOT NULL DEFAULT 0,
    verified    BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_otp_verifications_email ON otp_verifications(email);
CREATE INDEX IF NOT EXISTS idx_otp_verifications_expires_at ON otp_verifications(expires_at);

COMMENT ON TABLE otp_verifications IS
    'Codigos temporales OTP de un solo uso para verificacion de correo en onboarding y 2FA';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'erp_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE otp_verifications TO erp_app';
    END IF;
END
$$;
