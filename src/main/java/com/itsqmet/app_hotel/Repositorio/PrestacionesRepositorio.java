package com.itsqmet.app_hotel.Repositorio;


import com.itsqmet.app_hotel.Entidad.Prestaciones;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PrestacionesRepositorio extends JpaRepository<Prestaciones, Long> {
    List<Prestaciones> findByNombreContainingIgnoreCase(String nombre);

}
