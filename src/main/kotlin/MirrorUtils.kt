package burp

import java.net.URL
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

class MirrorUtils {
    companion object {
        fun makeMirrorRequest(
            reflectedParameters: List<String>,
            requestResponse: IHttpRequestResponse,
            tool: String,
            title: String,
            callbacks: IBurpExtenderCallbacks,
            displayUrl: String? = null
        ): MirrorItem {
            val now = LocalDateTime.now()
            val dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            val dateTime = now.format(dateFormatter) ?: ""
            val requestInfo = callbacks.helpers.analyzeRequest(requestResponse)
            val response = if (requestResponse.response != null) {
                callbacks.helpers.analyzeResponse(requestResponse.response)
            } else {
                null
            }
            return MirrorItem(
                requestResponse = callbacks.saveBuffersToTempFiles(requestResponse),
                dateTime = dateTime,
                host = requestInfo.url.host,
                url = requestInfo.url,
                displayUrl = displayUrl ?: requestInfo.url.toString(),
                tool = tool,
                parameters = reflectedParameters,
                method = requestInfo?.method ?: "",
                statusCode = response?.statusCode ?: 0,
                title = title,
                length = requestResponse.response?.size ?: 0,
                mimeType = response?.inferredMimeType ?: "",
                protocol = requestInfo?.url?.protocol ?: "",
                file = requestInfo?.url?.file ?: "",
                comments = requestResponse.comment ?: "",
            )
        }
    }
}

data class MirrorItem(
    val requestResponse: IHttpRequestResponsePersisted,
    val dateTime: String,
    val host: String,
    val url: URL,
    val displayUrl: String,
    val tool: String,
    val parameters: List<String>,
    val method: String,
    val statusCode: Short,
    val title: String,
    val length: Int,
    val mimeType: String,
    val protocol: String,
    val file: String,
    var comments: String,
)
