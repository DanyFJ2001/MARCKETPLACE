package com.itsqmet.app_hotel.Servicio;

import com.itsqmet.app_hotel.Entidad.Resenas;
import com.itsqmet.app_hotel.Repositorio.ResenaRepositorio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class ResenaServicio {
    @Autowired
    ResenaRepositorio resenaRepositorio;
    public List<Resenas> mostrarResenas(){
        return resenaRepositorio.findAll();
    }
    public List<Resenas> buscarResena(Date fechacomentario) {
        if (fechacomentario == null) {
            return resenaRepositorio.findAll(); // Si no se proporciona fecha, devuelve todas las reseñas
        } else {
            return resenaRepositorio.findByFechacomentario(fechacomentario); // Filtra por fecha si hay una
        }
    }

    public void guardarResena(Resenas resenas){
        resenaRepositorio.save(resenas);
    }
    public void eliminarResena(Long id){
        resenaRepositorio.deleteById(id);
    }
    public Optional <Resenas> buscarResenaId(Long id){
        return resenaRepositorio.findById(id);
    }
}
