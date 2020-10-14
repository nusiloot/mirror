package burp

class MirrorListener(private val callbacks: IBurpExtenderCallbacks, private val mirrorTab: MirrorTab) : IHttpListener {

    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse?) {
        messageInfo?.let { resReq ->
            val req = callbacks.helpers.analyzeRequest(resReq) ?: return

            if (callbacks.isInScope(req.url)) {
                if (!messageIsRequest && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && req.method == "GET") {
                    resReq.response =
                        MirrorInjector(resReq, mirrorTab.mirrorPanel.mirrorFilters.mirrorOptions, callbacks).inject()
                }

                if (!messageIsRequest &&
                    (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER)
                ) {
                    MirrorReflect(callbacks, mirrorTab.mirrorPanel).mirrorScan(resReq, toolFlag)
                }
            }
        }
    }
}
