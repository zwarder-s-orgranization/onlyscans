package lab.repairdesk.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod.GET
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
class RepairSecurity {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain = http
        .cors(withDefaults())
        .formLogin(withDefaults())
        .authorizeHttpRequests { rules ->
            rules.requestMatchers(GET, "/api/catalog/services").permitAll()
            rules.requestMatchers(GET, "/api/pickup/export").permitAll()
            rules.requestMatchers("/api/pickup/**").hasRole("MECHANIC")
            rules.requestMatchers("/api/customer/**").authenticated()
            rules.anyRequest().denyAll()
        }
        .build()
}
