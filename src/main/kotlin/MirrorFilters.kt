package burp

import java.awt.Color
import java.awt.FlowLayout
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSplitPane
import javax.swing.JTextField
import javax.swing.SwingUtilities

class MirrorFilters(
    private val mirrorPanel: MirrorPanel,
    private val server: Server,
    private val callbacks: IBurpExtenderCallbacks
) {
    val panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
    private val loadPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
    private val filterBar = JTextField("", 20)
    private val filterPanel = JPanel(FlowLayout(FlowLayout.LEFT))
    val mirrorOptions = MirrorOptions(callbacks)
    private val mirrorServer = JButton(startServer)

    init {
        val clearButton = JButton("Clear Items")
        val filterLabel = JLabel("Filter Items:")
        val filterButton = JButton("Filter")
        val resetButton = JButton("Reset")
        val optionsButton = JButton("Options")
        if (mirrorOptions.runServerOnStart.isSelected) {
            mirrorServer.text = stopServer
            mirrorServer.background = Color.GREEN
        } else {
            mirrorServer.text = startServer
            mirrorServer.background = Color.RED
        }
        val importProxyHistory = JButton("Import Proxy History")

        clearButton.addActionListener { clearMirrorItems() }
        filterBar.addActionListener { filterMirrorItems() }
        filterButton.addActionListener { filterMirrorItems() }
        resetButton.addActionListener { resetFilter() }
        optionsButton.addActionListener { mirrorOptions.optionFrame.isVisible = true }
        mirrorServer.addActionListener { startStopMirrorServer() }
        importProxyHistory.addActionListener {
            SwingUtilities.invokeLater {
                MirrorReflect(callbacks, mirrorPanel).importProxyHistory()
            }
        }
        filterPanel.apply {
            add(filterLabel)
            add(filterBar)
            add(filterButton)
            add(resetButton)
        }

        loadPanel.apply {
            add(clearButton)
            add(optionsButton)
            add(mirrorServer)
            add(importProxyHistory)
        }

        panel.apply {
            leftComponent = filterPanel
            rightComponent = loadPanel
            dividerSize = 0
        }
    }

    fun filtered(): Boolean {
        return if (filterBar.text.isNotEmpty()) {
            filterMirrorItems()
            true
        } else {
            false
        }
    }

    private fun filterMirrorItems() {
        SwingUtilities.invokeLater {
            val searchText = filterBar.text.toLowerCase()
            var filteredMirrorItems = this.mirrorPanel.model.mirrorItems
            if (searchText.isNotEmpty()) {
                filteredMirrorItems = filteredMirrorItems
                    .filter {
                        it.comments.toLowerCase().contains(searchText) ||
                            it.url.toString().toLowerCase().contains(searchText) ||
                            callbacks.helpers.bytesToString(it.requestResponse.request).toLowerCase().contains(
                                searchText
                            ) ||
                            callbacks.helpers.bytesToString(
                                it.requestResponse.response ?: ByteArray(0)
                            ).toLowerCase().contains(
                                searchText
                            )
                    }.toMutableList()
            }
            mirrorPanel.model.refreshMirror(filteredMirrorItems)
        }
    }

    private fun resetFilter() {
        filterBar.text = ""
        mirrorPanel.model.refreshMirror()
        mirrorPanel.requestViewer?.setMessage(ByteArray(0), true)
        mirrorPanel.responseViewer?.setMessage(ByteArray(0), false)
    }

    private fun clearMirrorItems() {
        mirrorPanel.model.clearMirror()
        mirrorPanel.requestViewer?.setMessage(ByteArray(0), true)
        mirrorPanel.responseViewer?.setMessage(ByteArray(0), false)
    }

    private fun startStopMirrorServer() {
        if (mirrorServer.text == startServer) {
            serverOnOptions()
            mirrorServer.apply {
                text = stopServer
                background = Color.GREEN
            }
            server.start()
        } else {
            mirrorServer.apply {
                text = startServer
                background = Color.RED
            }
            server.stop()
        }
    }

    private fun serverOnOptions() {
        mirrorOptions.apply {
            injectJavaScript.isSelected = true
            mirrorOptions.removeCsp.isSelected = true
        }
    }

    companion object {
        const val stopServer = "Server On"
        const val startServer = "Server Off"
    }
}
