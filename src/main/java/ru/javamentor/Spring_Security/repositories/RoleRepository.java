package ru.javamentor.Spring_Security.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import ru.javamentor.Spring_Security.models.Role;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    @Query("SELECT DISTINCT r FROM Role r WHERE r.name = :name")
    Optional<Role> findByName(String name);

    List<Role> findAllByIdIn(Collection<Long> ids);
}