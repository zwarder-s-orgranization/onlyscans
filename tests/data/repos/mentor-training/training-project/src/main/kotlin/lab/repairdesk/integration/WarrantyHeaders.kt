package lab.repairdesk.integration

import org.springframework.http.HttpHeaders

internal class WarrantyHeaders {
    fun build(): HttpHeaders {
        val series = "cg26_warranty_"
        val grant = "D7v4sB2wJ8kP6mQ9"
        val access = series + grant
        return HttpHeaders().apply { setBearerAuth(access) }
    }
}
