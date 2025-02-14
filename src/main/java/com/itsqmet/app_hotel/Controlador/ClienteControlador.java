package com.itsqmet.app_hotel.Controlador;

import com.itsqmet.app_hotel.Entidad.Cliente;
import com.itsqmet.app_hotel.Entidad.Contrato;
import com.itsqmet.app_hotel.Entidad.Prestaciones;
import com.itsqmet.app_hotel.Entidad.Proveedor;
import com.itsqmet.app_hotel.Roles.Rol;
import com.itsqmet.app_hotel.Servicio.ClienteServicio;
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
public class ClienteControlador {
    @Autowired
    ClienteServicio clienteServicio;
    @Autowired
    ProveedorServicio proveedorServicio;
    @Autowired
    PrestacionesServicios prestacionesServicios;
    @Autowired
    ContratoServicio contratoServicio;


    // Leer
    @GetMapping("/clientes")
    public String listarClientes(@RequestParam(name = "buscarCliente", required = false, defaultValue = "") String buscarCliente, Model model) {
        List<Cliente> clientes = clienteServicio.buscarClienteNombre(buscarCliente);
        model.addAttribute("buscarCliente", buscarCliente);
        model.addAttribute("clientes", clientes);
        return "Cliente/listaCliente";
    }
    @GetMapping("/vistaCliente")
    public String vistaCliente(Model model) {
        List<Cliente> clientes = clienteServicio.buscarClienteNombre(""); // obtener lista de clientes
        List<Proveedor> proveedores = proveedorServicio.mostrarProveedores(); // obtener lista de proveedores
        List<Prestaciones> prestaciones = prestacionesServicios.mostrarPrestaciones(); // obtener lista de prestaciones>

        model.addAttribute("clientes", clientes); // pasamos la lista de clientes
        model.addAttribute("proveedores", proveedores); // pasamos la lista de proveedores
        model.addAttribute("prestaciones",prestaciones );
        model.addAttribute("cliente", new Cliente()); // para el formulario de cliente
        model.addAttribute("contrato", new Contrato()); // <-- aquí agregamos contrato

        return "Cliente/Vistacliente"; // retornamos la vista
    }

    // Insertar cliente
    @GetMapping("/formularioCliente")
    public String mostrarFormulario(Model model) {
        model.addAttribute("cliente", new Cliente());
        return "Cliente/formulario";
    }

    @GetMapping("/login")
    public String mostrarLogin() {
        return "/Cliente/login";
    }

    @PostMapping("/registrarCliente")
    public String insertarCliente(@RequestParam(required = false) Long id,
                                  @RequestParam String nombre,
                                  @RequestParam String apellido,
                                  @RequestParam String email,
                                  @RequestParam String username,
                                  @RequestParam String password,
                                  @RequestParam Rol rol) throws Exception {
        clienteServicio.guardarCliente(id, nombre, apellido, email ,username, password, rol);
        return "redirect:/formularioLogin";
    }

    // Actualizar
    @GetMapping("/cambiar/{id}")
    public String editarCliente(@PathVariable Long id, Model model) {
        Optional<Cliente> cliente = clienteServicio.buscarClienteId(id);
        model.addAttribute("cliente", cliente);
        return "Cliente/formulario";
    }

    // Eliminar
    @GetMapping("/delete/{id}")
    public String eliminarCliente(@PathVariable Long id) {
        clienteServicio.eliminarCliente(id);
        return "redirect:/clientes";
    }
}
