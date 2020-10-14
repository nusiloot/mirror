package burp

class MirrorReflect(
    private val callbacks: IBurpExtenderCallbacks,
    private val mirrorPanel: MirrorPanel,
) {
    private val helpers: IExtensionHelpers = callbacks.helpers
    private val mirrorOptions = mirrorPanel.mirrorFilters.mirrorOptions

    fun mirrorScan(
        requestResponse: IHttpRequestResponse,
        toolFlag: Int = IBurpExtenderCallbacks.TOOL_PROXY
    ) {
        val request = callbacks.helpers.analyzeRequest(requestResponse) ?: return
        val highlightProxyHistory = mirrorOptions.highlightProxyHistory.isSelected

        mirrorScannerItems(request, requestResponse, toolFlag)?.let {

            if (mirrorPanel.addMirrorItem(it)) {
                if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && highlightProxyHistory) {
                    requestResponse.highlight = "purple"
                    requestResponse.comment =
                        "Mirror"
                }
            }
        }
    }

    private fun mirrorScannerItems(
        requestInfo: IRequestInfo,
        requestResponse: IHttpRequestResponse,
        toolFlag: Int
    ): MirrorItem? {
        val filteredParameters = requestInfo.parameters.mapNotNull { it.value }.filter { it.length > 3 }.distinct()

        val reflectedParameters =
            filteredParameters.filter { param ->
                checkReflectedParameter(param, requestResponse) || checkReflectedParameter(
                    helpers.urlDecode(
                        param.replace("%", "%25")
                    ),
                    requestResponse
                )
            }

        return if (reflectedParameters.isNotEmpty()) {
            val title = getTitle(requestResponse.response)
            val tool = callbacks.getToolName(toolFlag)
            MirrorUtils.makeMirrorRequest(
                reflectedParameters,
                requestResponse,
                tool,
                title,
                callbacks
            )
        } else {
            null
        }
    }

    private fun checkReflectedParameter(param: String, requestResponse: IHttpRequestResponse): Boolean {
        val response = String(requestResponse.response)
        return response.contains(param)
    }

    private fun getTitle(response: ByteArray?): String {
        if (response == null) return ""
        val html = callbacks.helpers.bytesToString(response)
        val titleRegex = "<title>(.*?)</title>".toRegex()
        val title = titleRegex.find(html)?.value ?: ""
        return title.removePrefix("<title>").removeSuffix("</title>")
    }

    fun importProxyHistory() {
        callbacks.proxyHistory.forEach {
            mirrorScan(it)
        }
    }
}
