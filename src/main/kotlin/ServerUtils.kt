package burp

class ServerUtils {
    companion object {
        fun findRequest(
            url: String,
            callbacks: IBurpExtenderCallbacks
        ): IHttpRequestResponse? {
            return callbacks.proxyHistory.asSequence().filter { filterProxyParams(it, url, callbacks) }
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
