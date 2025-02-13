package com.itsqmet.app_hotel.Servicio;

import com.itextpdf.text.DocumentException;
import com.itsqmet.app_hotel.Entidad.Prestaciones;
import com.itsqmet.app_hotel.Repositorio.PrestacionesRepositorio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Service
public class PrestacionesServicios {
    @Autowired
    PrestacionesRepositorio prestacionesRepositorio;
    public List<Prestaciones> mostrarPrestaciones(){return prestacionesRepositorio.findAll();}

    public Optional<Prestaciones> buscarPrestaciones(Long id){return prestacionesRepositorio.findById(id);}

    public List<Prestaciones> buscarPrestacionesPorNombre(String nombre){
        if (nombre != null  || nombre.isEmpty()) {
            return prestacionesRepositorio.findAll();
        } else {
            return prestacionesRepositorio.findByNombreContainingIgnoreCase(nombre);
        }
    }
    public void  guardarPrestaciones(Prestaciones prestaciones){ prestacionesRepositorio.save(prestaciones); }

    public void eliminarPrestaciones(Long id){ prestacionesRepositorio.deleteById(id); }


}
