package ru.javamentor.Spring_Security.services;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import ru.javamentor.Spring_Security.models.Role;
import ru.javamentor.Spring_Security.models.User;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface UserService {
    List<User> getAllUsers();

    User getUserById(Long id);

    Optional<User> findByUsername(String username);

    void saveUser(User user);

    void deleteUser(Long id);

    void addRoleToUser(Long userId, Role role) throws UsernameNotFoundException, IllegalArgumentException;

    void updateUser(User user, List<Long> roleIds);

    boolean existsByUsername(String username);

    String authUser(Authentication authentication);

    String regUser(User user);

    String createUser(User user, Set<Long> roleIds);

    void contUpdateUser(Long id, String username, String password, List<Long> roleIds);
}