package ru.javamentor.Spring_Security.controllers;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.javamentor.Spring_Security.exceptions.PasswordException;
import ru.javamentor.Spring_Security.exceptions.UserNameException;
import ru.javamentor.Spring_Security.exceptions.UserRoleException;
import ru.javamentor.Spring_Security.models.User;
import ru.javamentor.Spring_Security.repositories.RoleRepository;
import ru.javamentor.Spring_Security.services.UserService;

import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping
public class MainController {

    private final UserService userService;
    private final RoleRepository roleRepository;

    @Autowired
    public MainController(UserService userService, RoleRepository roleRepository) {
        this.userService = userService;
        this.roleRepository = roleRepository;
    }

    @GetMapping("/")
    public String showWelcomePage(Authentication authentication, Model model) {
        model.addAttribute("message", "Добро пожаловать!");
        return userService.authUser(authentication);
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
        model.addAttribute(createLoginAtribyte(logout, error));
        return "login";
    }

    private Map<String, String> createLoginAtribyte(Boolean logout, Boolean error) {
        Map<String, String> result = new HashMap<>();
        if (Boolean.TRUE.equals(error)) {
            result.put("error", "Неверный логин или пароль");
        }
        if (Boolean.TRUE.equals(logout)) {
            result.put("message", "Вы успешно вышли из системы");
        }
        return result;
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute("user") @Valid User user,
                               BindingResult result) {
        try {
            return userService.regUser(user);
        } catch (UserRoleException e) {
            result.reject("error.registration", "Ошибка при регистрации: " + e.getMessage());
        } catch (PasswordException e) {
            result.rejectValue("password", "error.password", e.getMessage());
        } catch (UserNameException e) {
            result.rejectValue("username", "error.username", e.getMessage());
        }
        return "register";
    }
}