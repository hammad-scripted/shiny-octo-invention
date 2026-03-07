package org.example.springsecuritydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((requests) -> requests.requestMatchers("/h2-console/**").permitAll()
                        .anyRequest().authenticated() // All URLs are protected
                        // to make our api stateless so that they can't remember previous data
                ).sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).headers(headers->headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)).csrf(AbstractHttpConfigurer::disable)
                // Enables the default login page
//                .formLogin(Customizer.withDefaults())
                // Enables "Basic" authentication for API testing (Postman/curl)
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }

    @Bean

    public UserDetailsService userDetailsService() {  // ✅ Remove the parameter
        UserDetails user = User.withUsername("user").password(passwordEncoder().encode("password")).roles("USER").build();
        UserDetails admin = User.withUsername("admin").password(passwordEncoder().encode("password")).roles("ADMIN").build();

        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

        if (!jdbcUserDetailsManager.userExists("user"))
            jdbcUserDetailsManager.createUser(user);

        if (!jdbcUserDetailsManager.userExists("admin"))
            jdbcUserDetailsManager.createUser(admin);
//        return new InMemoryUserDetailsManager(user,admin); for in memory
        return jdbcUserDetailsManager;  // ✅ Return THIS, not the parameter
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}