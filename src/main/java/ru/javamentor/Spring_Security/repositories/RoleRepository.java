package ru.javamentor.Spring_Security.repositories;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import ru.javamentor.Spring_Security.models.Role;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    @EntityGraph(attributePaths = {"users"})
    Optional<Role> findByName(String name);

    @EntityGraph(attributePaths = {"users"})
    List<Role> findAllByIdIn(Collection<Long> ids);
}