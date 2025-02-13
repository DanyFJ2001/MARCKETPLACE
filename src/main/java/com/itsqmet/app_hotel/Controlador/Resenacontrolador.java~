package com.itsqmet.app_hotel.Controlador;

import com.itsqmet.app_hotel.Entidad.Cliente;
import com.itsqmet.app_hotel.Entidad.Proveedor;
import com.itsqmet.app_hotel.Entidad.Resenas;
import com.itsqmet.app_hotel.Servicio.ClienteServicio;
import com.itsqmet.app_hotel.Servicio.ProveedorServicio;
import com.itsqmet.app_hotel.Servicio.ResenaServicio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Controller
public class Resenacontrolador {
    @Autowired
    ResenaServicio resenaServicio;
    @Autowired
    ProveedorServicio proveedorServicio;
    @Autowired
    ClienteServicio clienteServicio;

    @GetMapping("/resenas")
    public String listarResenas(
            @RequestParam(name = "buscarResenas", required = false) @DateTimeFormat(pattern = "yyyy-MM-dd")
            Date buscarResenas, Model model) {
        List<Resenas> resenas = resenaServicio.buscarResena(buscarResenas);
        model.addAttribute("resenas", resenas);
        return "Resenas/listaResenas";
    }

    //Mostrar formulario
    @GetMapping("/formularioResenas")
    public String mostrarFormularioResenas(Model model) {
        List<Proveedor> proveedores = proveedorServicio.mostrarProveedores();
        List<Cliente> clientes = clienteServicio.mostrarClientes();
        model.addAttribute("resenas", new Resenas());
        model.addAttribute("proveedores", proveedores);
        model.addAttribute("clientes", clientes);
        return "Resenas/formulario";

    }
    //Insertar
    @PostMapping("/registrarResenas")
    public String insertarResenas(@ModelAttribute Resenas resenas) {
        resenaServicio.guardarResena(resenas);
        return "redirect:/resenas";
    }
    //actualizar
    @GetMapping("/actualizarResenas/{id}")
    public String editarResenas(@PathVariable Long id, Model model) {
        Optional<Resenas> resenas = resenaServicio.buscarResenaId(id);
        List<Cliente> clientes = clienteServicio.mostrarClientes();
        List<Proveedor> proveedores = proveedorServicio.mostrarProveedores();

        if (resenas.isPresent()) {
            model.addAttribute("resenas", resenas.get());
        } else {
            model.addAttribute("resenas", new Resenas());
        }

        model.addAttribute("clientes", clientes);
        model.addAttribute("proveedores", proveedores);

        return "Resenas/formulario";
    }
    //Eliminar
    @GetMapping("/eliminarResenas/{id}")
    public String eliminarResenas(@PathVariable Long id) {
        resenaServicio.eliminarResena(id);
        return "redirect:/resenas";
    }


}






