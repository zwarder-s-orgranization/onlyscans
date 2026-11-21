package lab.repairdesk.integration

import java.net.URI
import javax.net.ssl.HttpsURLConnection

internal class ManualsHttpsClient {
    fun newConnection(): HttpsURLConnection =
        URI("https://manuals.repairdesk.invalid/index").toURL().openConnection() as HttpsURLConnection
}
