package ru.javamentor.Spring_Security.controllers;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.javamentor.Spring_Security.models.Role;
import ru.javamentor.Spring_Security.models.User;
import ru.javamentor.Spring_Security.services.RoleService;
import ru.javamentor.Spring_Security.services.UserService;

import java.util.Collections;

@Controller
@RequestMapping
public class MainController {

    private final UserService userService;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public MainController(UserService userService,
                          RoleService roleService,
                          PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.roleService = roleService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/")
    public String showWelcomePage(Authentication authentication, Model model) {
        model.addAttribute("message", "Добро пожаловать!");
        if (authentication != null && authentication.isAuthenticated()) {
            if (authentication.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
                return "redirect:/admin";
            }
            return "redirect:/user";
        }
        return "login";
    }

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @GetMapping("/login")
    public String showLoginPage(@RequestParam(value = "error", required = false) Boolean error,
                                @RequestParam(value = "logout", required = false) Boolean logout,
                                Model model) {
        if (Boolean.TRUE.equals(error)) {
            model.addAttribute("error", "Неверный логин или пароль");
        }
        if (Boolean.TRUE.equals(logout)) {
            model.addAttribute("message", "Вы успешно вышли из системы");
        }
        return "login";
    }

   /* @GetMapping("/access-denied")
    public String showAccessDeniedPage() {
        return "access-denied";
    }
*/
    @PostMapping("/register")
    public String registerUser(@ModelAttribute("user") @Valid User user,
                               BindingResult result) {
        // Проверка пароля
        if (user.getPassword() == null || user.getPassword().length() < 4) {
            result.rejectValue("password", "error.password", "Пароль должен содержать минимум 4 символа");
        }

        // Проверка существования пользователя
        if (userService.existsByUsername(user.getUsername())) {
            result.rejectValue("username", "error.username", "Этот логин уже занят");
        }

        if (result.hasErrors()) {
            return "register";
        }

        try {
            Role userRole = roleService.findByName("ROLE_USER")
                    .orElseThrow(() -> new RuntimeException("Роль USER не найдена"));

            user.setRoles(Collections.singleton(userRole));
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            userService.saveUser(user);

            return "redirect:/login?success";
        } catch (Exception e) {
            result.reject("error.registration", "Ошибка при регистрации: " + e.getMessage());
            return "register";
        }
    }
}