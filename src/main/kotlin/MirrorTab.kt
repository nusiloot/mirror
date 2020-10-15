package burp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext
import java.awt.FlowLayout
import javax.swing.JButton
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.table.AbstractTableModel
import javax.swing.table.TableRowSorter

class MirrorTab(callbacks: IBurpExtenderCallbacks, server: Server) : ITab {
    val mirrorPanel = MirrorPanel(callbacks, server)

    override fun getTabCaption() = "Mirror"

    override fun getUiComponent() = mirrorPanel.panel
}

class MirrorPanel(private val callbacks: IBurpExtenderCallbacks, server: Server) {
    val mirrorFilters = MirrorFilters(this, server, callbacks)
    val model = MirrorModel(mirrorFilters)
    val table = JTable(model)
    private val mirrorItems = model.mirrorItems

    private val messageEditor = MessageEditor(callbacks)
    val requestViewer: IMessageEditor? = messageEditor.requestViewer
    val responseViewer: IMessageEditor? = messageEditor.responseViewer

    val panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)

    init {
        MirrorActions(this, callbacks)
        table.apply {
            autoResizeMode = JTable.AUTO_RESIZE_OFF
            columnModel.getColumn(0).preferredWidth = 50 // ID
            columnModel.getColumn(1).preferredWidth = 160 // date
            columnModel.getColumn(2).preferredWidth = 125 // host
            columnModel.getColumn(3).preferredWidth = 250 // url
            columnModel.getColumn(4).preferredWidth = 75 // tool
            columnModel.getColumn(5).preferredWidth = 300 // parameter
            columnModel.getColumn(6).preferredWidth = 150 // title
            columnModel.getColumn(7).preferredWidth = 50 // method
            columnModel.getColumn(8).preferredWidth = 50 // status
            columnModel.getColumn(9).preferredWidth = 50 // length
            columnModel.getColumn(10).preferredWidth = 50 // mime
            columnModel.getColumn(11).preferredWidth = 50 // protocol
            columnModel.getColumn(12).preferredWidth = 120 // comments
            setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
            rowSorter = TableRowSorter(model)
            autoscrolls = true
            autoCreateRowSorter = true
        }

        table.selectionModel.addListSelectionListener {
            if (table.selectedRow != -1) {
                val displayedMirrorItems = model.displayedMirrorItems
                val selectedRow = table.convertRowIndexToModel(table.selectedRow)
                val requestResponse = displayedMirrorItems[selectedRow].requestResponse
                messageEditor.requestResponse = requestResponse
                requestViewer?.setMessage(requestResponse.request, true)
                responseViewer?.setMessage(requestResponse.response ?: ByteArray(0), false)
            }
        }

        val repeatPanel = JPanel(FlowLayout(FlowLayout.LEFT))

        val repeatButton = JButton("Repeat Request")
        repeatButton.addActionListener { repeatRequest() }
        repeatPanel.add(repeatButton)

        val mirrorTable = JScrollPane(table)
        val reqResSplit =
            JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer?.component, responseViewer?.component)
        reqResSplit.resizeWeight = 0.5

        val repeatReqSplit =
            JSplitPane(JSplitPane.VERTICAL_SPLIT, repeatPanel, reqResSplit)

        val mirrorOptSplit =
            JSplitPane(JSplitPane.VERTICAL_SPLIT, mirrorFilters.panel, mirrorTable)

        panel.topComponent = mirrorOptSplit
        panel.bottomComponent = repeatReqSplit
        panel.resizeWeight = 0.5
        callbacks.customizeUiComponent(panel)
    }

    fun addMirrorItem(mirrorRequest: MirrorItem): Boolean {
        return if (!checkIfDuplicate(mirrorRequest)) {
            model.mirrorItems.add(mirrorRequest)
            model.filterOrRefresh()
            true
        } else {
            false
        }
    }

    private fun checkIfDuplicate(mirrorItem: MirrorItem): Boolean {
        return if (mirrorFilters.mirrorOptions.noDuplicateItems.isSelected) {
            if (mirrorFilters.mirrorOptions.ignoreHostDuplicates.isSelected) {
                mirrorItems.any { it.url.path == mirrorItem.url.path && it.parameters == mirrorItem.parameters }
            } else {
                mirrorItems.any { it.url.host == mirrorItem.url.host && it.url.path == mirrorItem.url.path && it.parameters == mirrorItem.parameters }
            }
        } else {
            false
        }
    }

    private fun repeatRequest() {
        table.selectionModel.clearSelection()

        GlobalScope.launch(Dispatchers.IO) {
            val requestResponse = try {
                callbacks.makeHttpRequest(messageEditor.httpService, requestViewer?.message)
            } catch (e: java.lang.RuntimeException) {
                RequestResponse(requestViewer?.message, null, messageEditor.httpService)
            }
            withContext(Dispatchers.Swing) {
                SwingUtilities.invokeLater {
                    responseViewer?.setMessage(requestResponse?.response ?: ByteArray(0), false)
                }
            }
        }
    }
}

class MessageEditor(callbacks: IBurpExtenderCallbacks) : IMessageEditorController {
    var requestResponse: IHttpRequestResponse? = null

    val requestViewer: IMessageEditor? = callbacks.createMessageEditor(this, true)
    val responseViewer: IMessageEditor? = callbacks.createMessageEditor(this, false)

    override fun getResponse(): ByteArray? = requestResponse?.response ?: ByteArray(0)

    override fun getRequest(): ByteArray? = requestResponse?.request

    override fun getHttpService(): IHttpService? = requestResponse?.httpService
}

class MirrorModel(private val mirrorFilters: MirrorFilters) : AbstractTableModel() {
    private val columns =
        listOf(
            "ID",
            "Added",
            "Host",
            "URL",
            "Tool",
            "Reflected Parameters",
            "Title",
            "Method",
            "Status",
            "Length",
            "MIME",
            "Protocol",
            "Comments"
        )
    var mirrorItems: MutableList<MirrorItem> = ArrayList()
    var displayedMirrorItems: MutableList<MirrorItem> = ArrayList()
        private set

    companion object {
        private const val COMMENTS = 12
    }

    override fun getRowCount(): Int = displayedMirrorItems.size

    override fun getColumnCount(): Int = columns.size

    override fun getColumnName(column: Int): String {
        return columns[column]
    }

    override fun getColumnClass(columnIndex: Int): Class<*> {
        return when (columnIndex) {
            0 -> java.lang.Integer::class.java
            in 1..7 -> String::class.java
            8 -> Short::class.java
            9 -> Integer::class.java
            in 10..12 -> String::class.java
            else -> throw IndexOutOfBoundsException("$columnIndex is out of bounds.")
        }
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {

        val mirrorItem = displayedMirrorItems[rowIndex]

        return when (columnIndex) {
            0 -> rowIndex
            1 -> mirrorItem.dateTime
            2 -> mirrorItem.host
            3 -> mirrorItem.displayUrl
            4 -> mirrorItem.tool
            5 -> mirrorItem.parameters.joinToString()
            6 -> mirrorItem.title
            7 -> mirrorItem.method
            8 -> mirrorItem.statusCode
            9 -> mirrorItem.length
            10 -> mirrorItem.mimeType
            11 -> mirrorItem.protocol
            12 -> mirrorItem.comments
            else -> ""
        }
    }

    override fun isCellEditable(rowIndex: Int, columnIndex: Int) = columnIndex == COMMENTS

    override fun setValueAt(value: Any?, rowIndex: Int, colIndex: Int) {
        val mirrorItem: MirrorItem = mirrorItems[rowIndex]
        when (colIndex) {
            11 -> mirrorItem.comments = value.toString()
            else -> return
        }
        filterOrRefresh()
    }

    fun removeMirrorItems(selectedMirrorItems: MutableList<MirrorItem>) {
        mirrorItems.removeAll(selectedMirrorItems)
        filterOrRefresh()
    }

    fun clearMirror() {
        mirrorItems.clear()
        filterOrRefresh()
    }

    fun filterOrRefresh() {
        if (!mirrorFilters.filtered()) {
            refreshMirror()
        }
    }

    fun refreshMirror(updatedMirrorItems: MutableList<MirrorItem> = mirrorItems) {
        displayedMirrorItems = updatedMirrorItems
        fireTableDataChanged()
    }
}

class RequestResponse(private var req: ByteArray?, private var res: ByteArray?, private var service: IHttpService?) :
    IHttpRequestResponse {

    override fun getComment(): String? = null

    override fun setComment(comment: String?) {}

    override fun getRequest() = req

    override fun getHighlight(): String? = null

    override fun getHttpService(): IHttpService? = service

    override fun getResponse() = res

    override fun setResponse(message: ByteArray?) {
        res = message
    }

    override fun setRequest(message: ByteArray?) {
        req = message
    }

    override fun setHttpService(httpService: IHttpService?) {
        service = httpService
    }

    override fun setHighlight(color: String?) {}
}
