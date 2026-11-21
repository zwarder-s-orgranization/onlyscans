package lab.repairdesk.config

import java.util.UUID
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.provisioning.InMemoryUserDetailsManager

@Configuration
class RepairAccounts {
    @Bean
    fun users(): UserDetailsService {
        val encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()
        fun account(name: String, role: String, passwordVariable: String) = User.withUsername(name)
            .password(encoder.encode(System.getenv(passwordVariable) ?: UUID.randomUUID().toString()))
            .roles(role)
            .build()

        return InMemoryUserDetailsManager(
            account("rider-copper", "CUSTOMER", "REPAIR_COPPER_PASSWORD"),
            account("rider-indigo", "CUSTOMER", "REPAIR_INDIGO_PASSWORD"),
            account("shift-mechanic", "MECHANIC", "REPAIR_MECHANIC_PASSWORD"),
        )
    }
}
