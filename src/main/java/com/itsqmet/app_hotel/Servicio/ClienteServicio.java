package com.itsqmet.app_hotel.Servicio;

import com.itsqmet.app_hotel.Entidad.Cliente;
import com.itsqmet.app_hotel.Repositorio.ClienteRepositorio;
import com.itsqmet.app_hotel.Roles.Rol; // Aquí se incluye el rol (si es necesario)
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.print.DocFlavor;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Service
@Primary
public class ClienteServicio   {


    @Autowired
    ClienteRepositorio clienteRepositorio;

    @Autowired
    private PasswordEncoder passwordEncoder; // Para encriptar la contraseña si es necesario

    // Mostrar todos los clientes
    public List<Cliente> mostrarClientes() {
        return clienteRepositorio.findAll();
    }

    // Buscar clientes por nombre
    public List<Cliente> buscarClienteNombre(String buscarCliente) {
        if (buscarCliente == null || buscarCliente.isEmpty()) {
            return clienteRepositorio.findAll();
        } else {
            return clienteRepositorio.findByNombreContainingIgnoreCase(buscarCliente);
        }
    }

    // Guardar o actualizar cliente
    public void guardarCliente(Long id, String nombre, String apellido, String email, String username, String password, Rol rol) {
        Cliente cliente;

        if (id != null) {
            cliente = clienteRepositorio.findById(id).orElse(new Cliente());
        } else {
            cliente = new Cliente();
        }

        cliente.setNombre(nombre);
        cliente.setApellido(apellido);
        cliente.setEmail(email);
        cliente.setUsername(username);

        if (password != null && !password.isEmpty()) {
            cliente.setPassword(passwordEncoder.encode(password)); // Encriptamos la contraseña
        }

        // Aquí podríamos agregar el rol si es necesario (ejemplo: cliente tiene rol USER)
        cliente.setRol(rol);

        clienteRepositorio.save(cliente);
    }

    // Eliminar cliente
    public void eliminarCliente(Long id) {
        clienteRepositorio.deleteById(id);
    }

    // Buscar cliente por ID
    public Optional<Cliente> buscarClienteId(Long id) {
        return clienteRepositorio.findById(id);
    }


    // Método para cargar un cliente por su nombre de usuario (similar a UserDetailsService)

}
