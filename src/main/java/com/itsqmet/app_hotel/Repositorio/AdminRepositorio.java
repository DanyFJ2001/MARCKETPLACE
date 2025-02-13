package com.itsqmet.app_hotel.Repositorio;

import com.itsqmet.app_hotel.Entidad.Admin;
import com.itsqmet.app_hotel.Entidad.Cliente;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AdminRepositorio extends JpaRepository<Admin, Long> {
    List<Admin> findByNombreContainingIgnoreCase(String nombre);
    Admin findByUsername(String username);
}
