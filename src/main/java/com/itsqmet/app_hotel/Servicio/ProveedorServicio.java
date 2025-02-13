package com.itsqmet.app_hotel.Servicio;

import com.itsqmet.app_hotel.Entidad.Proveedor;
import com.itsqmet.app_hotel.Repositorio.ProveedorRepositorio;
import com.itsqmet.app_hotel.Roles.Rol;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import jakarta.transaction.Transactional;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Service
public class ProveedorServicio  {

    @Autowired
    private ProveedorRepositorio proveedorRepositorio;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public List<Proveedor> mostrarProveedores() {
        return proveedorRepositorio.findAll();
    }

    public List<Proveedor> buscarProveedorNombre(String buscarProveedor) {
        if (buscarProveedor == null || buscarProveedor.isEmpty()) {
            return proveedorRepositorio.findAll();
        } else {
            return proveedorRepositorio.findByNombreContainingIgnoreCase(buscarProveedor);
        }
    }

    public Optional<Proveedor> buscarProveedor(Long id) {
        return proveedorRepositorio.findById(id);
    }

    @Transactional
    public void guardarProveedor(Long id, String nombre, String especialidad, String experiencia, String tarifas, String correo, String telefono, String username, String password, Rol rol) {
        Proveedor proveedor;

        if (id != null) {
            proveedor = proveedorRepositorio.findById(id).orElse(new Proveedor());
        } else {
            proveedor = new Proveedor();
        }

        proveedor.setNombre(nombre);
        proveedor.setEspecialidad(especialidad);
        proveedor.setExperiencia(experiencia);
        proveedor.setTarifas(tarifas);
        proveedor.setCorreo(correo);
        proveedor.setTelefono(telefono);
        proveedor.setUsername(username);
        proveedor.setPassword(passwordEncoder.encode(password));
        proveedor.setRol(rol);

        proveedorRepositorio.save(proveedor);
    }

    public void eliminarProveedor(Long id) {
        proveedorRepositorio.deleteById(id);
    }



}
