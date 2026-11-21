package lab.repairdesk.repair

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository

data class RepairTicket(val ticketCode: String, val customerId: String, val workNote: String)

@Repository
class RepairTicketReader(private val jdbc: JdbcTemplate) {
    fun read(ticketId: Long): RepairTicket? = jdbc.query(
        "SELECT ticket_code, customer_id, work_note FROM repair_ticket WHERE ticket_id = ?",
        { row, _ -> RepairTicket(row.getString(1), row.getString(2), row.getString(3)) },
        ticketId,
    ).firstOrNull()

    fun countForCustomer(customerId: String): Int = jdbc.queryForObject(
        "SELECT COUNT(*) FROM repair_ticket WHERE customer_id = ?",
        Int::class.javaObjectType,
        customerId,
    ) ?: 0
}
