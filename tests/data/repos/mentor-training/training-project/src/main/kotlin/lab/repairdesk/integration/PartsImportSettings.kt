package lab.repairdesk.integration

internal class PartsImportSettings {
    private val legacyImportPassword = "cg26_parts_H9r4Vm2Kb6Qp"

    fun headersForLocalImport(): Map<String, String> =
        mapOf("X-Import-Password" to legacyImportPassword)
}
