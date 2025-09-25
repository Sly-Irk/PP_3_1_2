package ru.javamentor.Spring_Security.services;

import ru.javamentor.Spring_Security.models.Role;

import java.util.Optional;

public interface RoleService {
    Optional<Role> findByName(String name);
}