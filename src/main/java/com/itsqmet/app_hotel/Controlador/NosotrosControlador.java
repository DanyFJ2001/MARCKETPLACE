package com.itsqmet.app_hotel.Controlador;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
@Controller
public class NosotrosControlador {
    @GetMapping("/nosotros")
    public String mostrarNosotros() {
        return "/Resenas/nosotros";  // Thymeleaf buscará src/main/resources/templates/nosotros.html
    }
}
