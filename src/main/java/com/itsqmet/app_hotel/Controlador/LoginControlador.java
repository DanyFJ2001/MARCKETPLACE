package com.itsqmet.app_hotel.Controlador;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginControlador {
    @GetMapping("/formularioLogin")
    public String mostrarLogin() {
        return "Login/Login";
    }

    @GetMapping("/postLogin")
    public String reridigirPoRol(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login?error";
        }

        User usuario = (User) authentication.getPrincipal();
        String role = usuario.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .findFirst()
                .orElse("");

        if (role.equals("ROLE_ADMIN")) {
            return "redirect:/vistaAdmin";
        } else if (role.equals("ROLE_CLIENTE")) {
            return "redirect:/vistaCliente";
        } else if (role.equals("ROLE_PROVEEDOR")) {
            return "redirect:/vistaProveedor";
        }

        return "redirect:/login?error";
    }
}