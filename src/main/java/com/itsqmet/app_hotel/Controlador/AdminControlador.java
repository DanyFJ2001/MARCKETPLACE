package com.itsqmet.app_hotel.Controlador;

import com.itsqmet.app_hotel.Entidad.Admin;
import com.itsqmet.app_hotel.Entidad.Contrato;
import com.itsqmet.app_hotel.Entidad.Prestaciones;
import com.itsqmet.app_hotel.Entidad.Proveedor;
import com.itsqmet.app_hotel.Roles.Rol;
import com.itsqmet.app_hotel.Servicio.AdminServicio;
import com.itsqmet.app_hotel.Servicio.ContratoServicio;
import com.itsqmet.app_hotel.Servicio.PrestacionesServicios;
import com.itsqmet.app_hotel.Servicio.ProveedorServicio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Optional;

@Controller
public class AdminControlador {
    @Autowired
    AdminServicio adminServicio;
    @Autowired
    ProveedorServicio proveedorServicio;
    @Autowired
    PrestacionesServicios prestacionesServicios;
    @Autowired
    ContratoServicio contratoServicio;

    // Leer
    @GetMapping("/admins")
    public String listarAdmins(@RequestParam(name = "buscarAdmin", required = false, defaultValue = "") String buscarAdmin, Model model) {
        List<Admin> admins = adminServicio.buscarAdminNombre(buscarAdmin);
        model.addAttribute("buscarAdmin", buscarAdmin);
        model.addAttribute("admins", admins);
        return "Admin/listaAdmin";
    }

    @GetMapping("/vistaAdmin")
    public String vistaAdmin(Model model) {
        List<Admin> admins = adminServicio.buscarAdminNombre(""); // obtener lista de admins
        List<Proveedor> proveedores = proveedorServicio.mostrarProveedores(); // obtener lista de proveedores
        List<Prestaciones> prestaciones = prestacionesServicios.mostrarPrestaciones(); // obtener lista de prestaciones

        model.addAttribute("admins", admins); // pasamos la lista de admins
        model.addAttribute("proveedores", proveedores); // pasamos la lista de proveedores
        model.addAttribute("prestaciones", prestaciones); // pasamos la lista de prestaciones
        model.addAttribute("admin", new Admin()); // para el formulario de admin
        model.addAttribute("contrato", new Contrato()); // agregamos contrato

        return "Admin/VistaAdmin"; // retornamos la vista
    }

    // Insertar admin
    @GetMapping("/formularioAdmin")
    public String mostrarFormulario(Model model) {
        model.addAttribute("admin", new Admin());
        return "Admin/formulario";
    }

    @GetMapping("/loginAdmin")
    public String mostrarLogin() {
        return "/Admin/loginAdmin";
    }

    @PostMapping("/registrarAdmin")
    public String insertarAdmin(@RequestParam(required = false) Long id,
                                @RequestParam String nombre,
                                @RequestParam String apellido,
                                @RequestParam String email,
                                @RequestParam String username,
                                @RequestParam String password,
                                @RequestParam Rol rol) throws Exception {
        adminServicio.guardarAdmin(id, nombre, apellido, email, username, password, rol);
        return "redirect:/formularioLogin";
    }

    // Actualizar
    @GetMapping("/cambiarAdmin/{id}")
    public String editarAdmin(@PathVariable Long id, Model model) {
        Optional<Admin> admin = adminServicio.buscarAdminId(id);
        model.addAttribute("admin", admin);
        return "Admin/formulario";
    }

    // Eliminar
    @GetMapping("/deleteAdmin/{id}")
    public String eliminarAdmin(@PathVariable Long id) {
        adminServicio.eliminarAdmin(id);
        return "redirect:/admins";
    }
}
