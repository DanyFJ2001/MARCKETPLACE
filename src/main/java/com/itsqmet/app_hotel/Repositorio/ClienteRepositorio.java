package com.itsqmet.app_hotel.Repositorio;

import com.itsqmet.app_hotel.Entidad.Cliente;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

@Repository
public interface ClienteRepositorio extends JpaRepository<Cliente, Long> {
    List<Cliente> findByNombreContainingIgnoreCase(String nombre);
    Cliente findByUsername(String username);
}