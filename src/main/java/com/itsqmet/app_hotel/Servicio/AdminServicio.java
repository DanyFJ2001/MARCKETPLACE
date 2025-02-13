package com.itsqmet.app_hotel.Servicio;

import com.itsqmet.app_hotel.Entidad.Admin;  // Cambio: clase Admin
  // Cambio: repositorio de Admin
import com.itsqmet.app_hotel.Repositorio.AdminRepositorio;
import com.itsqmet.app_hotel.Roles.Rol;  // El rol sigue siendo necesario
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

import java.util.List;
import java.util.Optional;

@Service
public class AdminServicio {

    @Autowired
    AdminRepositorio adminRepositorio;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // Mostrar todos los admins
    public List<Admin> mostrarAdmins() {
        return adminRepositorio.findAll();
    }

    // Buscar admins por nombre
    public List<Admin> buscarAdminNombre(String buscarAdmin) {
        if (buscarAdmin == null || buscarAdmin.isEmpty()) {
            return adminRepositorio.findAll();
        } else {
            return adminRepositorio.findByNombreContainingIgnoreCase(buscarAdmin);
        }
    }

    // Guardar o actualizar admin
    public void guardarAdmin(Long id, String nombre, String apellido, String email, String username, String password, Rol rol) {
        Admin admin;

        if (id != null) {
            admin = adminRepositorio.findById(id).orElse(new Admin());
        } else {
            admin = new Admin();
        }

        admin.setNombre(nombre);
        admin.setApellido(apellido);
        admin.setEmail(email);
        admin.setUsername(username);

        if (password != null && !password.isEmpty()) {
            admin.setPassword(passwordEncoder.encode(password)); // Encriptamos la contraseña
        }

        // Aquí agregamos el rol (para admin, debería ser ADMIN)
        admin.setRol(rol);

        adminRepositorio.save(admin);
    }

    // Eliminar admin
    public void eliminarAdmin(Long id) {
        adminRepositorio.deleteById(id);
    }

    // Buscar admin por ID
    public Optional<Admin> buscarAdminId(Long id) {
        return adminRepositorio.findById(id);
    }


}
