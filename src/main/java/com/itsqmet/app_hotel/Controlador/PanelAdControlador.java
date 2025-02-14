package com.itsqmet.app_hotel.Controlador;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PanelAdControlador {
    @GetMapping("/panelA")
    public String mostrarPanel(){
        return "Admin/vistaAdmin";
    }

}
