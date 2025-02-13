package com.itsqmet.app_hotel.Entidad;

import com.itsqmet.app_hotel.Roles.Rol;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

@Entity
public class Proveedor {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "El nombre es obligatorio")
    @Size(min = 2, max = 50, message = "El nombre debe tener entre 2 y 50 caracteres")
    private String nombre;

    @NotBlank(message = "La especialidad es obligatoria")
    @Size(min = 2, max = 100, message = "La especialidad debe tener entre 2 y 100 caracteres")
    private String especialidad;

    @NotBlank(message = "La experiencia es obligatoria")
    @Size(min = 2, max = 100, message = "La experiencia debe tener entre 2 y 100 caracteres")
    private String experiencia;

    @NotBlank(message = "Las tarifas son obligatorias")
    private String tarifas;

    @NotBlank(message = "El correo es obligatorio")
    @Size(max = 100, message = "El correo no puede tener más de 100 caracteres")
    @Pattern(regexp = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}$", message = "El correo no tiene un formato válido")
    private String correo;

    @NotBlank(message = "El teléfono es obligatorio")
    @Size(min = 10, max = 13, message = "El teléfono debe tener entre 10 y 13 caracteres")
    private String telefono;

    @NotBlank(message = "El nombre de usuario es obligatorio")
    @Size(min = 3, max = 50, message = "El nombre de usuario debe tener entre 3 y 50 caracteres")
    private String username;

    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 6, message = "La contraseña debe tener al menos 6 caracteres")
    private String password;

    @Enumerated(EnumType.STRING)
    private Rol rol; // Aquí el rol del proveedor

    @OneToMany(mappedBy = "proveedor")
    private List<Prestaciones> prestaciones;

    @OneToMany(mappedBy = "proveedor")
    private List<Resenas> reseñas;

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getEspecialidad() {
        return especialidad;
    }

    public void setEspecialidad(String especialidad) {
        this.especialidad = especialidad;
    }

    public String getExperiencia() {
        return experiencia;
    }

    public void setExperiencia(String experiencia) {
        this.experiencia = experiencia;
    }

    public String getTarifas() {
        return tarifas;
    }

    public void setTarifas(String tarifas) {
        this.tarifas = tarifas;
    }

    public String getCorreo() {
        return correo;
    }

    public void setCorreo(String correo) {
        this.correo = correo;
    }

    public String getTelefono() {
        return telefono;
    }

    public void setTelefono(String telefono) {
        this.telefono = telefono;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Rol getRol() {
        return rol;
    }

    public void setRol(Rol rol) {
        this.rol = rol;
    }

    public List<Prestaciones> getPrestaciones() {
        return prestaciones;
    }

    public void setPrestaciones(List<Prestaciones> prestaciones) {
        this.prestaciones = prestaciones;
    }

    public List<Resenas> getReseñas() {
        return reseñas;
    }

    public void setReseñas(List<Resenas> reseñas) {
        this.reseñas = reseñas;
    }
}
