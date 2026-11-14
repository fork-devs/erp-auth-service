-- =============================================================================
-- ERP AUTH SERVICE - V16: METADATOS Y SCOPING EN OTP_VERIFICATIONS
-- =============================================================================
-- Añade tenant_id, user_id y purpose a la tabla otp_verifications para
-- soportar tipado estricto por Value Objects y scoping de auditoría.
-- =============================================================================

ALTER TABLE otp_verifications ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE otp_verifications ADD COLUMN IF NOT EXISTS user_id UUID;
ALTER TABLE otp_verifications ADD COLUMN IF NOT EXISTS purpose VARCHAR(50) NOT NULL DEFAULT 'EMAIL_VERIFICATION';

CREATE INDEX IF NOT EXISTS idx_otp_verifications_tenant_id ON otp_verifications(tenant_id);
CREATE INDEX IF NOT EXISTS idx_otp_verifications_user_id ON otp_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_otp_verifications_email_purpose ON otp_verifications(email, purpose);
