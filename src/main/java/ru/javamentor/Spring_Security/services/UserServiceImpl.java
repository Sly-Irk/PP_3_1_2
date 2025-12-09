package ru.javamentor.Spring_Security.services;

import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    public UserServiceImpl(UserRepository userRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    private Role getOrCreateRole(String name) {
        return roleRepository.findByName(name)
                .orElseGet(() -> {
                    Role role = new Role();
                    role.setName(name);
                    return roleRepository.save(role);
                });
    }

    private Set<Role> resolveRoles(List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return Collections.emptySet();
        }
        List<Role> found = roleRepository.findAllByIdIn(ids);
        if (found.size() != ids.size()) {
            Set<Long> foundIds = found.stream().map(Role::getId).collect(Collectors.toSet());
            List<Long> missing = ids.stream().filter(id -> !foundIds.contains(id)).toList();
            throw new IllegalArgumentException("Роли с ID " + missing + " не найдены");
        }
        return new HashSet<>(found);
    }

    private boolean isPasswordEncoded(String password) {
        return password != null && password.startsWith("$2a$");
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
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + id));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean existsByUsername(String username) {
        return userRepository.findByUsername(username).isPresent();
    }

    @Override
    public void saveUser(User user) {

        if (user.getId() == null) {
            if (existsByUsername(user.getUsername())) {
                throw new IllegalArgumentException("Username already exists");
            }
        } else {
            User existing = getUserById(user.getId());
            if (!existing.getUsername().equals(user.getUsername()) &&
                    existsByUsername(user.getUsername())) {
                throw new IllegalArgumentException("Username already exists");
            }
        }

        if (!isPasswordEncoded(user.getPassword())) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }

        userRepository.save(user);
    }

    @Override
    public void updateUser(User user, List<Long> roleIds) {

        User existing = getUserById(user.getId());

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        User current = userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new UsernameNotFoundException("Current user not found"));

        boolean isAdmin = current.getRoles().stream()
                .anyMatch(r -> "ROLE_ADMIN".equals(r.getName()));

        if (!isAdmin && !current.getId().equals(user.getId())) {
            throw new SecurityException("You can only edit your own profile");
        }

        if (!existing.getUsername().equals(user.getUsername())) {
            if (existsByUsername(user.getUsername())) {
                throw new IllegalArgumentException("Username already exists");
            }
            existing.setUsername(user.getUsername());
        }
        if (user.getPassword() != null && !user.getPassword().isEmpty()) {
            if (!isPasswordEncoded(user.getPassword())) {
                existing.setPassword(passwordEncoder.encode(user.getPassword()));
            } else {
                existing.setPassword(user.getPassword());
            }
        }
        if (roleIds != null && !roleIds.isEmpty()) {
            existing.setRoles(resolveRoles(roleIds));
        }
        userRepository.save(existing);
    }

    @Override
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    @Override
    public void addRoleToUser(Long userId, Role role) {

        User user = getUserById(userId);

        Role managed =
                roleRepository.findById(role.getId())
                        .orElseThrow(() -> new IllegalArgumentException("Role not found"));

        if (user.getRoles().contains(managed)) {
            throw new IllegalArgumentException("User already has this role");
        }
        user.addRole(managed);
        userRepository.save(user);
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
    public String authUser(Authentication auth) {
        if (auth != null && auth.isAuthenticated()) {
            boolean isAdmin = auth.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

            return isAdmin ? "redirect:/admin" : "redirect:/user";
        }
        return "login";
    }

    @Override
    public String createUser(User user, Set<Long> roleIds) {

        if (user.getPassword().length() < 4) {
            throw new PasswordException("Пароль должен содержать минимум 4 символа");
        }
        if (existsByUsername(user.getUsername())) {
            throw new UserNameExistException("Этот логин уже занят");
        }
        Set<Role> roles;
        if (roleIds == null || roleIds.isEmpty()) {
            roles = Collections.singleton(getOrCreateRole("ROLE_USER"));
        } else {
            roles = resolveRoles(new ArrayList<>(roleIds));
        }
        user.setRoles(roles);
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        userRepository.save(user);
        return "redirect:/admin";
    }

    @Override
    public String regUser(User user) {

        if (user.getPassword().length() < 4) {
            throw new PasswordException("Пароль должен содержать минимум 4 символа");
        }
        if (existsByUsername(user.getUsername())) {
            throw new UserNameException("Этот логин уже занят");
        }
        String selected = user.getSelectedRole();
        if (!"ADMIN".equals(selected) && !"USER".equals(selected)) {
            selected = "USER";
        }
        Role role = getOrCreateRole("ROLE_" + selected);

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
            user.setRoles(resolveRoles(roleIds));
        }
        updateUser(user, roleIds);
    }
}