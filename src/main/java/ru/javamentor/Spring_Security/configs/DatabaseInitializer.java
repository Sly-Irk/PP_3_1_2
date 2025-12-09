package ru.javamentor.Spring_Security.configs;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import ru.javamentor.Spring_Security.models.Role;
import ru.javamentor.Spring_Security.models.User;
import ru.javamentor.Spring_Security.repositories.RoleRepository;
import ru.javamentor.Spring_Security.repositories.UserRepository;

import java.util.Set;

@Configuration
public class DatabaseInitializer {
    private Role getOrCreateRole(RoleRepository roleRepository, String name) {
        return roleRepository.findByName(name)
                .orElseGet(() -> {
                    Role role = new Role();
                    role.setName(name);
                    return roleRepository.save(role);
                });
    }

    @Bean
    @Transactional
    public CommandLineRunner initDatabase(UserRepository userRepository,
                                          RoleRepository roleRepository,
                                          PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.count() == 0) {
                Role adminRole = getOrCreateRole(roleRepository, "ROLE_ADMIN");
                Role userRole = getOrCreateRole(roleRepository, "ROLE_USER");
                User admin = new User();
                admin.setUsername("admin");
                admin.setPassword(passwordEncoder.encode("admin"));
                admin.setRoles(Set.of(adminRole, userRole));
                userRepository.save(admin);
                System.out.println("=== ADMIN CREATED | login=admin | password=admin ===");
            }
        };
    }
}