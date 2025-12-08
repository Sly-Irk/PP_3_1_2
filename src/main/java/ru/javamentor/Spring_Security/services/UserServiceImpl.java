package ru.javamentor.Spring_Security.services;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.javamentor.Spring_Security.exceptions.PasswordException;
import ru.javamentor.Spring_Security.exceptions.UserNameException;
import ru.javamentor.Spring_Security.exceptions.UserNameExistException;
import ru.javamentor.Spring_Security.models.Role;
import ru.javamentor.Spring_Security.models.User;
import ru.javamentor.Spring_Security.repositories.RoleRepository;
import ru.javamentor.Spring_Security.repositories.UserRepository;

import java.util.*;
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
        if (user.getId() == null) {
            if (userRepository.findByUsername(user.getUsername()).isPresent()) {
                throw new IllegalArgumentException("Username already exists");
            }
        } else {
            User existingUser = userRepository.findById(user.getId())
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            if (!existingUser.getUsername().equals(user.getUsername()) &&
                    userRepository.findByUsername(user.getUsername()).isPresent()) {
                throw new IllegalArgumentException("Username already exists");
            }
        }
        if (user.getPassword() != null && !user.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        userRepository.save(user);
    }

    @Override
    @Transactional
    public void updateUser(User user, List<Long> roleIds) {
        if (user == null || user.getId() == null) {
            throw new IllegalArgumentException("User and user ID cannot be null");
        }
        User existingUser = userRepository.findById(user.getId())
                .orElseThrow(() -> new UsernameNotFoundException(
                        String.format("User not found with id: %d", user.getId())));

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new UsernameNotFoundException("Current user not found"));

        if (currentUser.getRoles().stream().noneMatch(r -> "ROLE_ADMIN".equals(r.getName()))) {
            if (!currentUser.getId().equals(user.getId())) {
                throw new SecurityException("You can only edit your own profile");
            }
        }
        if (!existingUser.getUsername().equals(user.getUsername())) {
            if (existsByUsername(user.getUsername())) {
                throw new IllegalArgumentException(
                        String.format("Username '%s' already exists", user.getUsername()));
            }
            existingUser.setUsername(user.getUsername());
        }
        if (user.getPassword() != null && !user.getPassword().trim().isEmpty()) {
            existingUser.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        if (roleIds != null && !roleIds.isEmpty()) {
            Set<Role> managedRoles = new HashSet<>(roleRepository.findAllByIdIn(roleIds));

            if (managedRoles.size() != roleIds.size()) {
                List<Long> foundIds = managedRoles.stream().map(Role::getId).toList();
                List<Long> missingIds = roleIds.stream()
                        .filter(id -> !foundIds.contains(id))
                        .toList();
                throw new IllegalArgumentException(
                        String.format("Roles with IDs %s not found", missingIds));
            }
            if (!existingUser.getRoles().equals(managedRoles)) {
                existingUser.setRoles(managedRoles);
            }
        }
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

    @Override
    public String authUser(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            if (authentication.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
                return "redirect:/admin";
            }
            return "redirect:/user";
        }
        return "login";
    }

    @Override
    public String createUser(User user, Set<Long> roleIds) {
        if (user.getPassword() == null || user.getPassword().length() < 4) {
            throw new PasswordException("Пароль должен содержать минимум 4 символа");
        }
        if (existsByUsername(user.getUsername())) {
            throw new UserNameExistException("Этот логин уже занят");
        }
        Set<Role> roles = new HashSet<>();
        if (roleIds != null && !roleIds.isEmpty()) {
            List<Role> foundRoles = roleRepository.findAllByIdIn(new ArrayList<>(roleIds));

            if (foundRoles.size() != roleIds.size()) {
                Set<Long> foundIds = foundRoles.stream()
                        .map(Role::getId)
                        .collect(Collectors.toSet());

                List<Long> missingIds = roleIds.stream()
                        .filter(id -> !foundIds.contains(id))
                        .collect(Collectors.toList());
                throw new IllegalArgumentException("Роли с ID " + missingIds + " не найдены");
            }
            roles.addAll(foundRoles);
        } else {
            Role defaultRole = roleRepository.findByName("ROLE_USER")
                    .orElseGet(() -> {
                        Role role = new Role();
                        role.setName("ROLE_USER");
                        return roleRepository.save(role);
                    });
            roles.add(defaultRole);
        }
        user.setRoles(roles);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "redirect:/admin";
    }

    @Override
    public String regUser(User user) {
        if (user.getPassword() == null || user.getPassword().length() < 4) {
            throw new PasswordException("Пароль должен содержать минимум 4 символа");
        }
        if (existsByUsername(user.getUsername())) {
            throw new UserNameException("Этот логин уже занят");
        }

        String selectedRole = user.getSelectedRole();
        if (selectedRole == null || (!selectedRole.equals("ADMIN") && !selectedRole.equals("USER"))) {
            selectedRole = "USER";
        }
        String roleName = "ROLE_" + selectedRole;
        Role role = roleRepository.findByName(roleName)
                .orElseGet(() -> {
                    Role newRole = new Role();
                    newRole.setName(roleName);
                    return roleRepository.save(newRole);
                });
        user.setRoles(Collections.singleton(role));
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "redirect:/login?success";
    }

    @Override
    public void contUpdateUser(Long id, String username, String password, List<Long> roleIds) {
        User user = getUserById(id);
        user.setUsername(username);

        if (password != null && !password.isEmpty()) {
            user.setPassword(passwordEncoder.encode(password));
        }

        if (roleIds != null && !roleIds.isEmpty()) {
            Set<Role> roles = new HashSet<>(roleRepository.findAllByIdIn(roleIds));
            user.setRoles(roles);
        }
        updateUser(user, roleIds);
    }
}