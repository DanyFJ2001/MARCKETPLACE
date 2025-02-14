package com.itsqmet.app_hotel.Seguridad;

import com.itsqmet.app_hotel.Servicio.UserDetailsServices;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class AutorizUsuario {

    @Autowired
    private UserDetailsServices userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        // Rutas públicas (accesibles sin autenticación)
                        .requestMatchers("/", "/formularioAdmin", "/formularioProveedor", "/formularioCliente", "/login", "/formularioLogin", "/formularioPrestaciones", "/panelA")
                        .permitAll()
                        // Permitir acceso a archivos estáticos (CSS, JS, imágenes)
                        .requestMatchers("/css/", "/js/", "/images/**").permitAll()
                        // Rutas de administración (solo ADMIN)
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        // Rutas de contratos (ADMIN y otros roles si es necesario)
                        .requestMatchers("/contratos", "/formularioContratos", "/registrarContratos", "/actualizarContratos/", "/eliminarContratos/").hasRole("ADMIN")
                        // Rutas de reseñas (ADMIN y otros roles si es necesario)
                        .requestMatchers("/resenas", "/formularioResenas", "/registrarResenas", "/actualizarResenas/", "/eliminarResenas/").hasRole("ADMIN")
                        // Ruta para generar PDF (solo ADMIN)
                        .requestMatchers("/generarPdf").hasRole("ADMIN")
                        // Rutas de cliente y proveedor (ADMIN puede acceder)
                        .requestMatchers("/vistaCliente").hasAnyRole("ADMIN", "CLIENTE")
                        .requestMatchers("/vistaProveedor").hasAnyRole("ADMIN", "PROVEEDOR")
                        // Cualquier otra ruta requiere autenticación
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/formularioLogin")
                        .permitAll()
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/postLogin", true)
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/formularioLogin?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}
