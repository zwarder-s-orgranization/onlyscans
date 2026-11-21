package lab.repairdesk.integration

import java.io.InputStream
import org.apache.commons.compress.archivers.dump.DumpArchiveInputStream
import org.apache.commons.lang3.StringUtils
import org.apache.commons.net.ftp.FTPClient
import org.apache.commons.text.StringSubstitutor
import org.json.JSONObject
import org.jsoup.Jsoup
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.http.HttpHeaders
import org.springframework.stereotype.Component

internal class LegacyIntake {
    fun receiptTitle(html: String): String = StringUtils.trimToEmpty(Jsoup.parse(html).title())

    fun manifestReference(json: String): String = JSONObject(json).getString("reference")

    fun renderNotice(template: String): String = StringSubstitutor.createInterpolator().replace(template)

    fun firstArchiveEntry(archive: InputStream): String? = DumpArchiveInputStream(archive).use {
        it.nextEntry?.name
    }

    fun archiveTransferClient(): FTPClient = FTPClient().apply { enterLocalPassiveMode() }
}

@Component
@ConditionalOnProperty("pickup.callback.enabled", havingValue = "true")
internal class PickupCallback(@Value("\${pickup.callback.authorization}") private val authorization: String) {
    fun headers(): HttpHeaders = HttpHeaders().apply { set(HttpHeaders.AUTHORIZATION, authorization) }
}
