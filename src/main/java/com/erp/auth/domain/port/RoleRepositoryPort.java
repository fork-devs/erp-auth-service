package com.erp.auth.domain.port;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface RoleRepositoryPort {
    Optional<Role> findById(UUID id);
    Optional<Role> findByCode(RoleCode code);
    Set<Role> findAllByCodes(Set<RoleCode> codes);
    List<Role> findAll();
}
