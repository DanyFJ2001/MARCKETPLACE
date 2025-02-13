package com.itsqmet.app_hotel.Repositorio;

import com.itsqmet.app_hotel.Entidad.Resenas;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

@Repository
public interface ResenaRepositorio extends JpaRepository<Resenas, Long> {
    List<Resenas> findByFechacomentario(Date fechacomentario);

}
