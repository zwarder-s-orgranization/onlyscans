package lab.repairdesk.integration

import java.net.URI
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection

internal class SupplierHttpsClient {
    fun newConnection(): HttpsURLConnection {
        val url = URI("https://supplier.repairdesk.invalid/catalog").toURL()
        return (url.openConnection() as HttpsURLConnection).apply {
            connectTimeout = 2_000
            readTimeout = 2_000
            hostnameVerifier = HostnameVerifier { _, _ -> true }
        }
    }
}
