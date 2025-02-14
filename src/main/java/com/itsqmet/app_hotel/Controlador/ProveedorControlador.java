package com.itsqmet.app_hotel.Controlador;

import com.itsqmet.app_hotel.Entidad.Cliente;
import com.itsqmet.app_hotel.Entidad.Prestaciones;
import com.itsqmet.app_hotel.Entidad.Proveedor;
import com.itsqmet.app_hotel.Roles.Rol;
import com.itsqmet.app_hotel.Servicio.PrestacionesServicios;
import com.itsqmet.app_hotel.Servicio.ProveedorServicio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@Controller
public class ProveedorControlador {

    @Autowired
    ProveedorServicio proveedorServicio;
    @Autowired
    PrestacionesServicios prestacionesServicios;

    // Leer proveedores
    @GetMapping("/proveedores")
    public String listarProveedores(@RequestParam(name = "buscarProveedor", required = false, defaultValue = "") String buscarProveedor, Model model) {
        List<Proveedor> proveedores = proveedorServicio.buscarProveedorNombre(buscarProveedor);
        model.addAttribute("buscarProveedor", buscarProveedor);
        model.addAttribute("proveedores", proveedores); // Cambié el nombre del atributo a 'proveedores'
        return "Proveedor/listaProveedor"; // Vista de proveedores
    }

    // Vista proveedor
    @GetMapping("/vistaProveedor")
    public String vistaProveedor(Model model) {
        List<Proveedor> proveedores = proveedorServicio.mostrarProveedores(); // obtener lista de proveedores
        model.addAttribute("proveedores", proveedores); // pasar la lista de proveedores
        model.addAttribute("prestacion", new Prestaciones()); // objeto vacío para el formulario de prestaciones
        return "Proveedor/VistaProveedor"; // nombre de la vista donde mostrarás el formulario
    }


    // Mostrar formulario proveedor
    @GetMapping("/formularioProveedor")
    public String mostrarFormularioProveedor(Model model) {
        model.addAttribute("proveedor", new Proveedor());
        return "Proveedor/formulario";
    }

    // Insertar proveedor
    @PostMapping("/registrarProveedor")
    public String insertarProveedor(@RequestParam(required = false) Long id,
                                    @RequestParam String nombre,
                                    @RequestParam String especialidad,
                                    @RequestParam String experiencia,
                                    @RequestParam String tarifas,
                                    @RequestParam String correo,
                                    @RequestParam String telefono,
                                    @RequestParam String username,
                                    @RequestParam String password,
                                    @RequestParam Rol rol) throws Exception {

        proveedorServicio.guardarProveedor(id, nombre, especialidad, experiencia, tarifas, correo, telefono, username, password, rol);
        return "redirect:/formularioLogin";
    }

    // Actualizar proveedor
    @GetMapping("/actualizarProveedor/{id}")
    public String editarProveedor(@PathVariable Long id, Model model) {
        Optional<Proveedor> proveedor = proveedorServicio.buscarProveedor(id);
        model.addAttribute("proveedor", proveedor.orElse(new Proveedor()));
        return "Proveedor/formulario";
    }

    // Eliminar proveedor
    @GetMapping("/eliminarProveedor/{id}")
    public String eliminarProveedor(@PathVariable Long id) {
        proveedorServicio.eliminarProveedor(id);
        return "redirect:/proveedores";
    }
}
