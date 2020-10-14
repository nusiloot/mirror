package burp

import java.util.Arrays

class MirrorInjector(
    requestResponse: IHttpRequestResponse,
    mirrorOptions: MirrorOptions,
    callbacks: IBurpExtenderCallbacks
) {
    private val helpers = callbacks.helpers
    private val response = requestResponse.response
    private val responseInfo = helpers.analyzeResponse(response)
    private var headers = responseInfo.headers
    private var body = Arrays.copyOfRange(response, responseInfo.bodyOffset, response.size)
    private val injectJs = mirrorOptions.injectJavaScript.isSelected
    private val rmCsp = mirrorOptions.removeCsp.isSelected

    fun inject(): ByteArray? {
        if (injectJs || rmCsp) {
            if (injectJs) {
                body = injectJavaScript()
            }

            if (rmCsp) {
                headers = removeCspHeader()
            }
        }

        return helpers.buildHttpMessage(headers, body)
    }

    private fun removeCspHeader(): List<String> {
        return headers.filterNot { it.startsWith("Content-Security-Policy:", true) }
    }

    private fun injectJavaScript(): ByteArray {
        val injectString = """
            <script src="http://localhost:3033/mirror/mirror.js"></script>
            </body>
        """.trimIndent()

        return helpers.bytesToString(body).replace("</body>", injectString).toByteArray()
    }
}
