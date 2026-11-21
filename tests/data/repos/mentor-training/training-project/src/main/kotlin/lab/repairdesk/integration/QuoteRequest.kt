package lab.repairdesk.integration

import java.net.URI
import java.net.http.HttpRequest

internal class QuoteRequest {
    private val pricingApiKey = "cg26_quote_qA7mN4kV9rT2sJ6c"

    fun build(): HttpRequest = HttpRequest.newBuilder(URI("https://parts.repairdesk.invalid/pricing"))
        .header("X-Api-Key", pricingApiKey)
        .GET()
        .build()
}
