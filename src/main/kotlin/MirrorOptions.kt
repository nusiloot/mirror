package burp

import java.awt.BorderLayout
import javax.swing.BoxLayout
import javax.swing.JCheckBox
import javax.swing.JFrame
import javax.swing.JPanel

class MirrorOptions(callbacks: IBurpExtenderCallbacks) {
    val optionFrame = JFrame("Mirror Options")
    private val fetchHistoryOnStart = JCheckBox("Fetch proxy history on start")
    val runServerOnStart = JCheckBox("Run Mirror server on start")
    val removeCsp = JCheckBox("Remove Content Security Policy (CSP) headers")
    val noDuplicateItems = JCheckBox("Ignore duplicate items")
    val ignoreHostDuplicates = JCheckBox("Ignore host when considering duplicate items")
    val injectJavaScript = JCheckBox("Inject Mirror server JavaScript")

    init {
        val optionsPanel = JPanel()
        fetchHistoryOnStart.isSelected = (callbacks.loadExtensionSetting(IMPORT_PROXY_ON_START) ?: "true").toBoolean()
        runServerOnStart.isSelected = (callbacks.loadExtensionSetting(RUN_SERVER_ON_START) ?: "false").toBoolean()
        injectJavaScript.isSelected = (callbacks.loadExtensionSetting(RUN_SERVER_ON_START) ?: "false").toBoolean()
        noDuplicateItems.isSelected = (callbacks.loadExtensionSetting(NO_DUP_ITEMS) ?: "true").toBoolean()
        removeCsp.isSelected = (callbacks.loadExtensionSetting(REMOVE_CSP_HEADERS) ?: "false").toBoolean()
        ignoreHostDuplicates.isSelected = (
            callbacks.loadExtensionSetting(IGNORE_HOST_DUPLICATES)
                ?: "false"
            ).toBoolean()

        fetchHistoryOnStart.addActionListener {
            callbacks.saveExtensionSetting(
                IMPORT_PROXY_ON_START,
                fetchHistoryOnStart.isSelected.toString()
            )
        }

        runServerOnStart.addActionListener {
            callbacks.saveExtensionSetting(
                RUN_SERVER_ON_START,
                runServerOnStart.isSelected.toString()
            )
        }

        removeCsp.addActionListener {
            callbacks.saveExtensionSetting(
                REMOVE_CSP_HEADERS,
                removeCsp.isSelected.toString()
            )
        }

        noDuplicateItems.addActionListener {
            callbacks.saveExtensionSetting(
                NO_DUP_ITEMS,
                noDuplicateItems.isSelected.toString()
            )
        }
        ignoreHostDuplicates.addActionListener {
            callbacks.saveExtensionSetting(
                IGNORE_HOST_DUPLICATES,
                ignoreHostDuplicates.isSelected.toString()
            )
        }

        optionsPanel.apply {
            this.layout = BoxLayout(optionsPanel, BoxLayout.Y_AXIS)
            add(fetchHistoryOnStart)
            add(noDuplicateItems)
            add(ignoreHostDuplicates)
            add(removeCsp)
            add(runServerOnStart)
            add(injectJavaScript)
        }
        optionFrame.apply {
            defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
            contentPane.add(optionsPanel, BorderLayout.CENTER)
            setLocationRelativeTo(null)
            pack()
        }
    }

    companion object {
        const val IMPORT_PROXY_ON_START = "import proxy on start"
        const val RUN_SERVER_ON_START = "run server ons start"
        const val NO_DUP_ITEMS = "no dup items"
        const val IGNORE_HOST_DUPLICATES = "ignore host on duplicates"
        const val REMOVE_CSP_HEADERS = "remove csp headers"
    }
}
