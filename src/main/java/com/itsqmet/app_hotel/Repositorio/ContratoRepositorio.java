package com.itsqmet.app_hotel.Repositorio;

import com.itsqmet.app_hotel.Entidad.Contrato;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ContratoRepositorio extends JpaRepository<Contrato, Long> {
  List<Contrato> findByNombreContratoContainingIgnoreCase(String nombreContrato);

}
