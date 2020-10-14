package burp

import java.awt.Toolkit
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.StringSelection
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPopupMenu

class MirrorActions(
    private val panel: MirrorPanel,
    private val callbacks: IBurpExtenderCallbacks
) : ActionListener {
    private val table = panel.table
    private val actionsMenu = JPopupMenu()
    private val sendToRepeater = JMenuItem("Send request(s) to Repeater")
    private val sendToIntruder = JMenuItem("Send request(s) to Intruder")
    private val copyURLs = JMenuItem("Copy URL(s)")
    private val deleteMenu = JMenuItem("Delete Items(s)")
    private val clearMenu = JMenuItem("Clear Items")
    private val comments = JMenuItem("Add comment")

    init {
        sendToRepeater.addActionListener(this)
        sendToIntruder.addActionListener(this)
        copyURLs.addActionListener(this)
        deleteMenu.addActionListener(this)
        clearMenu.addActionListener(this)
        actionsMenu.apply {
            add(sendToRepeater)
            add(sendToIntruder)
            add(copyURLs)
            addSeparator()
            add(deleteMenu)
            add(clearMenu)
            addSeparator()
        }
        comments.addActionListener(this)
        actionsMenu.addSeparator()
        actionsMenu.add(comments)
        panel.table.componentPopupMenu = actionsMenu
    }

    override fun actionPerformed(e: ActionEvent?) {
        if (table.selectedRow == -1) return
        val selectedMirrorItems = getSelectedMirrorItems()
        when (val source = e?.source) {
            deleteMenu -> {
                panel.model.removeMirrorItems(selectedMirrorItems)
            }
            clearMenu -> {
                panel.model.clearMirror()
                panel.requestViewer?.setMessage(ByteArray(0), true)
                panel.responseViewer?.setMessage(ByteArray(0), false)
            }
            copyURLs -> {
                val urls = selectedMirrorItems.map { it.url }.joinToString()
                val clipboard: Clipboard = Toolkit.getDefaultToolkit().systemClipboard
                clipboard.setContents(StringSelection(urls), null)
            }
            else -> {
                for (selectedMirrorItem in selectedMirrorItems) {
                    val https = useHTTPs(selectedMirrorItem)
                    val url = selectedMirrorItem.url
                    when (source) {
                        sendToRepeater -> {
                            var label = selectedMirrorItem.title
                            if (label.length > 10) {
                                label = label.substring(0, 9) + "+"
                            }
                            callbacks.sendToRepeater(
                                url.host,
                                url.port,
                                https,
                                selectedMirrorItem.requestResponse.request,
                                label
                            )
                        }
                        sendToIntruder -> {
                            callbacks.sendToIntruder(
                                url.host, url.port, https,
                                selectedMirrorItem.requestResponse.request, null
                            )
                        }
                        comments -> {
                            val newComments = JOptionPane.showInputDialog("Comments:", selectedMirrorItem.comments)
                            selectedMirrorItem.comments = newComments
                            panel.model.refreshMirror()
                        }
                    }
                }
            }
        }
    }

    private fun getSelectedMirrorItems(): MutableList<MirrorItem> {
        val selectedMirrorItem: MutableList<MirrorItem> = ArrayList()
        for (index in table.selectedRows) {
            val row = table.convertRowIndexToModel(index)
            selectedMirrorItem.add(panel.model.displayedMirrorItems[row])
        }
        return selectedMirrorItem
    }

    private fun useHTTPs(mirrorItem: MirrorItem): Boolean {
        return (mirrorItem.url.protocol.toLowerCase() == "https")
    }
}
