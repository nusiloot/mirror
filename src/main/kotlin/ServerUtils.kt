package burp

import java.net.URL

class ServerUtils {
    companion object {
        fun findRequest(
            url: String,
            callbacks: IBurpExtenderCallbacks
        ): IHttpRequestResponse? {
            val uri = URL(url)
            val host = uri.host
            val port = if (uri.port != -1) {
                uri.port
            } else {
                uri.defaultPort
            }

            val hostAndPort = "$host:$port"

            val constructUrl = if (url.contains(":$port", ignoreCase = true)) {
                url
            } else {
                url.replaceFirst(host, hostAndPort, ignoreCase = true)
            }

            return callbacks.proxyHistory.asSequence().filter { filterProxyParams(it, constructUrl, callbacks) }
                .firstOrNull()
        }

        private fun filterProxyParams(
            requestResponse: IHttpRequestResponse,
            url: String,
            callbacks: IBurpExtenderCallbacks
        ): Boolean {
            val helpers = callbacks.helpers
            val request = helpers.analyzeRequest(requestResponse)
            val reqUrl = request.url.toString()
            return reqUrl == callbacks.helpers.urlDecode(url)
        }
    }
}
