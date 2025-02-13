package com.itsqmet.app_hotel.Repositorio;

import com.itsqmet.app_hotel.Entidad.Cliente;
import com.itsqmet.app_hotel.Entidad.Proveedor;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ProveedorRepositorio extends JpaRepository<Proveedor, Long> {
    List<Proveedor> findByNombreContainingIgnoreCase(String nombre);
    Proveedor findByUsername(String username);

}
