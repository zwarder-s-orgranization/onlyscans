# Repair Desk: умышленные уязвимости

15 находок. Таблица для быстрой сверки; [эталон JSON](training-findings.json) содержит дополнительные участки и безопасные контрпримеры. [Описание полей](README.md).

| ID | Категория | Сложность | Где | Что уязвимо |
| --- | --- | --- | --- | --- |
| A-SEC-01 | SECRET | EASY | [PartsImportSettings.kt:4](../training-project/src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt#L4) | Пароль служебной учётной записи импорта записан в коде. |
| A-SEC-02 | SECRET | EASY | [QuoteRequest.kt:7](../training-project/src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt#L7) | Встроенный API-ключ передаётся в `X-Api-Key` при запросе прайса. |
| A-SEC-03 | SECRET | MEDIUM | [application.yml:13](../training-project/src/main/resources/application.yml#L13) | В конфигурации прописан bearer-токен для подтверждения выдачи. |
| A-SEC-04 | SECRET | MEDIUM | [DepotStatusClient.kt:8](../training-project/src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt#L8) | Если переменная окружения отсутствует, клиент статусов использует встроенный токен. |
| A-SEC-05 | SECRET | HARD | [WarrantyHeaders.kt:7–10](../training-project/src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt#L7-L10) | Токен портала гарантий собирается из двух строковых фрагментов перед отправкой запроса. |
| A-SCA-01 | SCA | EASY | [build.gradle.kts:31](../training-project/build.gradle.kts#L31) | `org.apache.commons:commons-text:1.9` — опасные подстановки при интерполяции недоверенного текста (CVE-2022-42889). |
| A-SCA-02 | SCA | EASY | [build.gradle.kts:32](../training-project/build.gradle.kts#L32) | `org.jsoup:jsoup:1.14.1` — обработка специально сформированного HTML может вызвать отказ в обслуживании (CVE-2021-37714). |
| A-SCA-03 | SCA | MEDIUM | [build.gradle.kts:33](../training-project/build.gradle.kts#L33) | `org.apache.commons:commons-compress:1.25.0` — обработка повреждённого DUMP-архива может зациклиться (CVE-2024-25710). |
| A-SCA-04 | SCA | MEDIUM | [build.gradle.kts:36](../training-project/build.gradle.kts#L36) | `commons-net:commons-net:3.8.0` — FTP-клиент доверяет хосту из ответа PASV (CVE-2021-37533). |
| A-SCA-05 | SCA | HARD | [build.gradle.kts:38](../training-project/build.gradle.kts#L38) | `org.json:json:20230227` — разбор вложенных составных ключей может исчерпать память (CVE-2023-5072). |
| A-SAST-01 | SAST | EASY | [RepairLookupController.kt:13–14](../training-project/src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt#L13-L14) | Параметр HTTP-запроса подставляется в SQL без параметризации. |
| A-SAST-02 | SAST | EASY | [SupplierHttpsClient.kt:13](../training-project/src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt#L13) | HTTPS-клиент поставщика принимает любое имя хоста в сертификате. |
| A-SAST-03 | SAST | MEDIUM | [RepairCors.kt:13–14](../training-project/src/main/kotlin/lab/repairdesk/config/RepairCors.kt#L13-L14) | CORS разрешает любой origin и передачу cookie для приватной сводки клиента. |
| A-SAST-04 | SAST | MEDIUM | [RepairSecurity.kt:18](../training-project/src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt#L18) | Служебная выгрузка выдачи доступна без входа и проверки роли. |
| A-SAST-05 | SAST | HARD | [RepairTicketReader.kt:10–11](../training-project/src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt#L10-L11) | Вошедший клиент может прочитать чужую заявку по её ID. |

Для SCA таблица фиксирует наличие уязвимой версии. Достижимость уязвимого кода из приложения проверяется отдельно.
