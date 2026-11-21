package lab.repairdesk.catalog

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class ServiceCatalogController {
    @GetMapping("/api/catalog/services")
    fun serviceNames() = listOf("Brake cable adjustment", "Wheel truing", "Gear indexing")
}
