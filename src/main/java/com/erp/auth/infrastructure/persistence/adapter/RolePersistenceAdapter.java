package com.erp.auth.infrastructure.persistence.adapter;

import com.erp.auth.domain.model.Role;
import com.erp.auth.domain.model.RoleCode;
import com.erp.auth.domain.port.RoleRepositoryPort;
import com.erp.auth.infrastructure.persistence.mapper.RolePersistenceMapper;
import com.erp.auth.infrastructure.persistence.repository.SpringDataRoleRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class RolePersistenceAdapter implements RoleRepositoryPort {

    private final SpringDataRoleRepository springDataRoleRepository;

    public RolePersistenceAdapter(SpringDataRoleRepository springDataRoleRepository) {
        this.springDataRoleRepository = springDataRoleRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<Role> findById(UUID id) {
        return springDataRoleRepository.findById(id)
                .map(RolePersistenceMapper::toDomain);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<Role> findByCode(RoleCode code) {
        return springDataRoleRepository.findByCode(code.name())
                .map(RolePersistenceMapper::toDomain);
    }

    @Override
    @Transactional(readOnly = true)
    public Set<Role> findAllByCodes(Set<RoleCode> codes) {
        Set<String> codeStrings = codes.stream().map(RoleCode::name).collect(Collectors.toSet());
        return springDataRoleRepository.findByCodeIn(codeStrings).stream()
                .map(RolePersistenceMapper::toDomain)
                .collect(Collectors.toSet());
    }

    @Override
    @Transactional(readOnly = true)
    public List<Role> findAll() {
        return springDataRoleRepository.findAll().stream()
                .map(RolePersistenceMapper::toDomain)
                .collect(Collectors.toList());
    }
}
