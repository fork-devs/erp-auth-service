ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;

CREATE POLICY users_tenant_isolation_policy ON users
    FOR ALL
    USING (
        current_setting('app.bypass_rls', true) = 'on'
        OR (
            nullif(current_setting('app.tenant_id', true), '') IS NOT NULL
            AND tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
        )
    );

CREATE POLICY user_roles_tenant_isolation_policy ON user_roles
    FOR ALL
    USING (
        current_setting('app.bypass_rls', true) = 'on'
        OR (
            nullif(current_setting('app.tenant_id', true), '') IS NOT NULL
            AND tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
        )
    );
