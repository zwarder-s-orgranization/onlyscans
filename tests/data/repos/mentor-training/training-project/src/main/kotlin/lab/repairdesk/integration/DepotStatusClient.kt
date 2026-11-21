package lab.repairdesk.integration

import java.net.URI
import java.net.http.HttpRequest

internal class DepotStatusClient {
    fun request(): HttpRequest {
        val access = System.getenv("DEPOT_STATUS_TOKEN") ?: "cg26_depot_mK7xR4bP9wD2qT"
        return HttpRequest.newBuilder(URI("https://depot.repairdesk.invalid/status"))
            .header("Authorization", "Bearer $access")
            .GET()
            .build()
    }
}
