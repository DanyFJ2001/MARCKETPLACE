package com.itsqmet.app_hotel.Controlador;

import com.itsqmet.app_hotel.Entidad.Prestaciones;
import com.itsqmet.app_hotel.Entidad.Proveedor;
import com.itsqmet.app_hotel.Servicio.PrestacionesServicios;
import com.itsqmet.app_hotel.Servicio.ProveedorServicio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@Controller
public class PrestacionesControlador {
    @Autowired
    PrestacionesServicios prestacionesServicios;
    @Autowired
    ProveedorServicio proveedorServicio;

    @GetMapping("/prestaciones")
    public String listarPrestaciones(@RequestParam(name = "buscarPrestaciones", required = false, defaultValue = "") String buscarPrestaciones, Model model) {
        List<Prestaciones> prestaciones = prestacionesServicios.buscarPrestacionesPorNombre(buscarPrestaciones);
        model.addAttribute("buscarPrestaciones", buscarPrestaciones);
        model.addAttribute("prestaciones", prestaciones);
        return "Prestaciones/listaPrestaciones";
    }

    @GetMapping("/formularioPrestaciones")
    public String mostrarFormularioPrestaciones(Model model) {
        List<Proveedor> proveedores = proveedorServicio.mostrarProveedores();
        model.addAttribute("proveedores", proveedores);
        return "Prestaciones/formulario";
    }

    @PostMapping("/registrarPrestaciones")
    public String insertarPrestaciones(@ModelAttribute Prestaciones prestacion) {
        prestacionesServicios.guardarPrestaciones(prestacion);
        return "redirect:/vistaProveedor";
    }


    @GetMapping("/actualizarPrestaciones/{id}")
    public String editarPrestaciones(@PathVariable Long id, Model model) {
        Optional<Prestaciones> optionalPrestacion = prestacionesServicios.buscarPrestaciones(id);
        if (optionalPrestacion.isPresent()) {
            model.addAttribute("prestacion", optionalPrestacion.get()); // ✅ Corrección aquí
        } else {
            return "redirect:/prestaciones"; // Evitar errores si no se encuentra el ID
        }
        return "Prestaciones/formulario";
    }


    @GetMapping("/prestaciones/{id}")
    public String eliminarPrestaciones(@PathVariable Long id, Model model) {
        Optional<Prestaciones> prestaciones = prestacionesServicios.buscarPrestaciones(id);
        prestacionesServicios.eliminarPrestaciones(id);

        return "redirect:/prestaciones";

    }
}
