package com.itsqmet.app_hotel.Servicio;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.*;
import com.itsqmet.app_hotel.Entidad.Contrato;
import com.itsqmet.app_hotel.Repositorio.ContratoRepositorio;
import jakarta.persistence.Entity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
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


    public byte[] generarPdfContratos() throws DocumentException, IOException {
        List<Contrato> contratos = contratoRepositorio.findAll();
        Document document = new Document(PageSize.A4, 36, 36, 90, 36);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfWriter writer = PdfWriter.getInstance(document, baos);


        BaseColor corporatePurple = new BaseColor(75, 46, 204);      // Color principal
        BaseColor lightPurple = new BaseColor(243, 241, 255);        // Fondo claro
        BaseColor mediumPurple = new BaseColor(133, 111, 224);       // Tono medio

        writer.setPageEvent(new PdfPageEventHelper() {
            public void onEndPage(PdfWriter writer, Document document) {
                try {
                    PdfContentByte cb = writer.getDirectContent();


                    Rectangle rect = new Rectangle(36, document.getPageSize().getHeight() - 60,
                            document.getPageSize().getWidth() - 36,
                            document.getPageSize().getHeight() - 36);
                    rect.setBackgroundColor(corporatePurple);
                    cb.rectangle(rect);





                    BaseFont bf = BaseFont.createFont(BaseFont.HELVETICA_BOLD, BaseFont.CP1252, BaseFont.NOT_EMBEDDED);
                    cb.beginText();
                    cb.setFontAndSize(bf, 11);
                    cb.setColorFill(BaseColor.WHITE);
                    cb.setTextMatrix(120, document.getPageSize().getHeight() - 50);
                    cb.showText("Workana   -    Plataforma de Trabajo y Contratación");
                    cb.endText();


                    cb.setLineWidth(0.5f);
                    cb.setColorStroke(mediumPurple);
                    cb.moveTo(36, 30);
                    cb.lineTo(document.getPageSize().getWidth() - 36, 30);
                    cb.stroke();


                    cb.beginText();
                    cb.setFontAndSize(bf, 8);
                    cb.setColorFill(BaseColor.GRAY);
                    cb.showTextAligned(PdfContentByte.ALIGN_CENTER,
                            "Workana © " + Calendar.getInstance().get(Calendar.YEAR) + " | Tel: +246810111 | Email: contacto@workana.com",
                            (document.getPageSize().getWidth()) / 2, 15, 0);
                    cb.endText();

                    cb.beginText();
                    cb.setFontAndSize(bf, 8);
                    cb.setColorFill(mediumPurple);
                    cb.showTextAligned(PdfContentByte.ALIGN_RIGHT,
                            "Página " + writer.getPageNumber(),
                            document.getPageSize().getWidth() - 40, 15, 0);
                    cb.endText();

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

        document.open();


        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 20, corporatePurple);
        Paragraph title = new Paragraph("Listado de Contratos", titleFont);
        title.setAlignment(Element.ALIGN_CENTER);
        title.setSpacingAfter(20);
        document.add(title);


        Font dateFont = FontFactory.getFont(FontFactory.HELVETICA, 10, BaseColor.GRAY);
        Paragraph date = new Paragraph();
        date.add(new Chunk("Fecha de generación: " +
                new SimpleDateFormat("dd/MM/yyyy HH:mm").format(new Date()), dateFont));
        date.setAlignment(Element.ALIGN_RIGHT);
        date.setSpacingAfter(20);
        document.add(date);


        PdfPTable table = new PdfPTable(new float[]{1, 3, 2.5f, 2.5f});
        table.setWidthPercentage(100);
        table.setSpacingBefore(10f);


        Font headerFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 11, BaseColor.WHITE);
        String[] headers = {"ID", "Nombre Contrato", "Fecha Inicio", "Fecha Fin"};
        for (String header : headers) {
            PdfPCell cell = new PdfPCell(new Phrase(header, headerFont));
            cell.setBackgroundColor(corporatePurple);
            cell.setPadding(8);
            cell.setHorizontalAlignment(Element.ALIGN_CENTER);
            table.addCell(cell);
        }

        Font contentFont = FontFactory.getFont(FontFactory.HELVETICA, 10);
        BaseColor zebraColor = lightPurple;
        int rowCount = 0;

        for (Contrato contrato : contratos) {
            BaseColor backgroundColor = (rowCount % 2 == 0) ? BaseColor.WHITE : zebraColor;

            PdfPCell cell;


            cell = new PdfPCell(new Phrase(String.valueOf(contrato.getId()), contentFont));
            cell.setHorizontalAlignment(Element.ALIGN_CENTER);
            cell.setPadding(6);
            cell.setBackgroundColor(backgroundColor);
            cell.setBorderColor(BaseColor.WHITE);
            cell.setBorderWidth(1);
            table.addCell(cell);


            cell = new PdfPCell(new Phrase(contrato.getNombreContrato(), contentFont));
            cell.setPadding(6);
            cell.setBackgroundColor(backgroundColor);
            cell.setBorderColor(BaseColor.WHITE);
            cell.setBorderWidth(1);
            table.addCell(cell);


            cell = new PdfPCell(new Phrase(String.valueOf(contrato.getFechaInicio()), contentFont));
            cell.setPadding(6);
            cell.setBackgroundColor(backgroundColor);
            cell.setBorderColor(BaseColor.WHITE);
            cell.setBorderWidth(1);
            table.addCell(cell);


            cell = new PdfPCell(new Phrase(String.valueOf(contrato.getFechaFin()), contentFont));
            cell.setPadding(6);
            cell.setBackgroundColor(backgroundColor);
            cell.setBorderColor(BaseColor.WHITE);
            cell.setBorderWidth(1);
            table.addCell(cell);

            rowCount++;
        }

        document.add(table);


        Font noteFont = FontFactory.getFont(FontFactory.HELVETICA_OBLIQUE, 9, BaseColor.GRAY);
        Paragraph note = new Paragraph();
        note.add(new Chunk("\nEste documento es una lista oficial de contratos registrados en Workana. " +
                "Para consultas, por favor contacte con nuestro servicio de atención al cliente.", noteFont));
        note.setSpacingBefore(15);
        document.add(note);

        document.close();
        return baos.toByteArray();
    }



}
