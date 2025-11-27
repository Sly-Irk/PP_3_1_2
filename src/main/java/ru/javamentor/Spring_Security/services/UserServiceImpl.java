package ru.javamentor.Spring_Security.services;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import ru.javamentor.Spring_Security.models.Role;
import ru.javamentor.Spring_Security.models.User;
import ru.javamentor.Spring_Security.repositories.RoleRepository;
import ru.javamentor.Spring_Security.repositories.UserRepository;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository userRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void grantUserRole(Long userId, Role role) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + userId));

        if (role == null) {
            throw new IllegalArgumentException("Role cannot be null");
        }

        Role managedRole = roleRepository.findById(role.getId())
                .orElseThrow(() -> new IllegalArgumentException("Role not found"));

        if (user.addRole(managedRole)) {
            userRepository.save(user);
        }
    }

    @Override
    public void registerNewUser(User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }

        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("Default role ROLE_USER not found"));

        user.addRole(userRole);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    @Override
    public boolean userHasRole(Long userId, String roleName) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return user.getRoles().stream()
                .anyMatch(role -> role.getName().equals(roleName));
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    @Transactional(readOnly = true)
    public User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public void saveUser(User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    @Override
    @Transactional
    public void updateUser(User user, List<Long> roleIds) {
        // 1. Проверка входных параметров
        if (user == null || user.getId() == null) {
            throw new IllegalArgumentException("User and user ID cannot be null");
        }
        // 2. Получение существующего пользователя
        User existingUser = userRepository.findById(user.getId())
                .orElseThrow(() -> new UsernameNotFoundException(
                        String.format("User not found with id: %d", user.getId())));
        // 3. Проверка прав доступа
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new UsernameNotFoundException("Current user not found"));

        if (currentUser.getRoles().stream().noneMatch(r -> "ROLE_ADMIN".equals(r.getName()))) {
            if (!currentUser.getId().equals(user.getId())) {
                throw new SecurityException("You can only edit your own profile");
            }
        }
        // 4. Проверка и обновление username
        if (!existingUser.getUsername().equals(user.getUsername())) {
            if (existsByUsername(user.getUsername())) {
                throw new IllegalArgumentException(
                        String.format("Username '%s' already exists", user.getUsername()));
            }
            existingUser.setUsername(user.getUsername());
        }
        // 5. Обновление пароля
        if (StringUtils.hasText(user.getPassword())) {
            existingUser.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        // 6. Обновление ролей (если переданы)
        if (roleIds != null && !roleIds.isEmpty()) {
            Set<Role> managedRoles = new HashSet<>(roleRepository.findAllByIdIn(roleIds));

            if (managedRoles.size() != roleIds.size()) {
                // List<Long> foundIds = managedRoles.stream().map(Role::getId).toList();
                List<Long> foundIds = managedRoles.stream().map(Role::getId).collect(Collectors.toList());
                List<Long> missingIds = roleIds.stream()
                        .filter(id -> !foundIds.contains(id)).collect(Collectors.toList());

                throw new IllegalArgumentException(
                        String.format("Roles with ids %s not found", missingIds));
            }

            if (!existingUser.getRoles().equals(managedRoles)) {
                existingUser.setRoles(managedRoles);
            }
        }
        // 7. Сохранение изменений (без аудита)
        userRepository.save(existingUser);
    }

    @Override
    @Transactional
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    @Override
    @Transactional
    public void addRoleToUser(Long userId, Role role) {
        if (userId == null) {
            throw new IllegalArgumentException("User ID cannot be null");
        }
        if (role == null || role.getId() == null) {
            throw new IllegalArgumentException("Role cannot be null and must have ID");
        }

        Role managedRole = roleRepository.findById(role.getId())
                .orElseThrow(() -> new IllegalArgumentException(
                        String.format("Role with id %d not found", role.getId())));

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException(
                        String.format("User with id %d not found", userId)));

        if (user.getRoles().stream().anyMatch(r -> r.getId().equals(managedRole.getId()))) {
            throw new IllegalArgumentException(
                    String.format("User %s already has role %s",
                            user.getUsername(), managedRole.getName()));
        }

        user.addRole(managedRole);
        userRepository.save(user);
    }

    @Override
    public void addRolesToUser(Long userId, Set<Role> roles) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        Set<Role> managedRoles = new HashSet<>();
        for (Role role : roles) {
            Role managedRole = roleRepository.findById(role.getId())
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Role not found with id: " + role.getId()));
            managedRoles.add(managedRole);
        }

        user.addRoles(managedRoles);
        userRepository.save(user);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean existsByUsername(String username) {
        return userRepository.findByUsername(username).isPresent();
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities()
        );
    }
}