@file:Suppress("unused")

package burp

import java.awt.Toolkit
import javax.swing.SwingUtilities

class BurpExtender : IBurpExtender, IExtensionStateListener {
    private val server = Server()

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        val tab = MirrorTab(callbacks, server)
        server.callbacks = callbacks
        server.tab = tab

        callbacks.apply {
            registerHttpListener(MirrorListener(callbacks, tab))
            printOutput("Mirror v0.0.1")
            printOutput("Author: Caleb Kinney")
            printOutput("Email: caleb@derail.io")
            printOutput("Website: https://derail.io")
            setExtensionName("Mirror")
        }

        SwingUtilities.invokeLater {
            callbacks.addSuiteTab(tab)
            if ((callbacks.loadExtensionSetting(MirrorOptions.IMPORT_PROXY_ON_START) ?: "true").toBoolean()) {
                MirrorReflect(callbacks, tab.mirrorPanel).importProxyHistory()
            }
        }

        if ((callbacks.loadExtensionSetting(MirrorOptions.RUN_SERVER_ON_START) ?: "false").toBoolean()) {
            server.start()
        }
    }

    override fun extensionUnloaded() {
        Toolkit.getDefaultToolkit().beep()
        server.stop()
    }
}
