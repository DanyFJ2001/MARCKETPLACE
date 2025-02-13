package com.itsqmet.app_hotel.Servicio;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;
import com.itsqmet.app_hotel.Entidad.Contrato;
import com.itsqmet.app_hotel.Repositorio.ContratoRepositorio;
import jakarta.persistence.Entity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Service
public class ContratoServicio {
    @Autowired
    ContratoRepositorio contratoRepositorio;

    public List<Contrato> mostrarContratos() {
        return contratoRepositorio.findAll();
    }

    public List<Contrato> buscarContratoPorNombre(String buscarContrato) {
        if (buscarContrato == null || buscarContrato.isEmpty()) {
            return contratoRepositorio.findAll();
        } else {
            return contratoRepositorio.findByNombreContratoContainingIgnoreCase(buscarContrato);
        }
    }

    public void guardarContrato(Contrato contrato) {
        contratoRepositorio.save(contrato);
    }

    public void eliminarContrato(Long id) {
        contratoRepositorio.deleteById(id);
    }
    public Optional <Contrato> buscarContratoId(Long id){return contratoRepositorio.findById(id);}


    public byte[] generarPdf() throws ExceptionInInitializerError, DocumentException, IOException {
        List<Contrato> contratos = contratoRepositorio.findAll();
        Document document = new Document();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfWriter.getInstance(document, baos);
        document.open();
        document.add(new Paragraph("Lista de Contratos", FontFactory.getFont("Arial", 14, Font.BOLD)));
        PdfPTable table = new PdfPTable(4);
        table.setWidthPercentage(100);
        table.addCell(new PdfPCell(new Phrase("ID", FontFactory.getFont("Arial", 12))));
        table.addCell(new PdfPCell(new Phrase("Nombre Contrato", FontFactory.getFont("Arial", 12))));
        table.addCell(new PdfPCell(new Phrase("Fecha Inicio", FontFactory.getFont("Arial", 12))));
        table.addCell(new PdfPCell(new Phrase("Fecha Fin", FontFactory.getFont("Arial", 12))));
        for (Contrato contrato : contratos) {
            table.addCell(new PdfPCell(new Phrase(String.valueOf(contrato.getId()), FontFactory.getFont("Arial", 11))));
            table.addCell(new PdfPCell(new Phrase(contrato.getNombreContrato(), FontFactory.getFont("Arial", 11))));
            table.addCell(new PdfPCell(new Phrase(String.valueOf(contrato.getFechaInicio()), FontFactory.getFont("Arial", 11))));
            table.addCell(new PdfPCell(new Phrase(String.valueOf(contrato.getFechaFin()), FontFactory.getFont("Arial", 11))));
        }
        document.add(table);
        document.close();
        return baos.toByteArray();
    }



}
