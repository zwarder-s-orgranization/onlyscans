package lab.repairdesk.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
class RepairCors {
    @Bean
    fun corsConfigurationSource(): UrlBasedCorsConfigurationSource {
        val customerSummary = CorsConfiguration().apply {
            allowedOriginPatterns = listOf("*")
            allowCredentials = true
            allowedMethods = listOf("GET")
        }
        return UrlBasedCorsConfigurationSource().apply {
            registerCorsConfiguration("/api/customer/summary", customerSummary)
        }
    }
}
