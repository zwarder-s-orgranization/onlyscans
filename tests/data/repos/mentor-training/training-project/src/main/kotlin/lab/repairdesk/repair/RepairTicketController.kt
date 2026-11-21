package lab.repairdesk.repair

import java.security.Principal
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/customer")
class RepairTicketController(private val reader: RepairTicketReader) {
    @GetMapping("/tickets/{ticketId}")
    fun getTicket(@PathVariable ticketId: Long): ResponseEntity<RepairTicket> =
        ResponseEntity.ofNullable(reader.read(ticketId))

    @GetMapping("/summary")
    fun summary(principal: Principal): Map<String, Any> =
        mapOf("customerId" to principal.name, "openTickets" to reader.countForCustomer(principal.name))
}
