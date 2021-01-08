from binaryninja import *
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, getMonospaceFont
from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractTableModel
from PySide2.QtWidgets import *
from PySide2.QtGui import (QFont, QFontMetricsF, QTextCursor, QBrush)

colors = {"black":   HighlightStandardColor.BlackHighlightColor,
          "cyan":    HighlightStandardColor.CyanHighlightColor,
          "green":   HighlightStandardColor.GreenHighlightColor,
          "magenta": HighlightStandardColor.MagentaHighlightColor,
          "orange":  HighlightStandardColor.OrangeHighlightColor,
          "red":     HighlightStandardColor.RedHighlightColor}


class TableModel(QAbstractTableModel):
    def __init__(self, data):
        super(TableModel, self).__init__()
        self._data = data
        self._patched = []
        self.COLUMN_HEADERS = [
            'Address',
            'Condition',
            'Taken',
            'New Cov'
        ]

        self._last_sort = 0
        self._last_sort_order = QtCore.Qt.AscendingOrder


    def data(self, index, role=QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole:
            column = index.column()
            return self._data[index.row()][index.column()]

        elif role == QtCore.Qt.ForegroundRole:
            return QBrush(Qt.black)

        elif role == QtCore.Qt.BackgroundRole:
            status = self._data[index.row()][2]
            addr = int(self._data[index.row()][0], 16)
            if addr in self._patched:
                return QBrush(Qt.blue)
            elif status == 'ALWAYS':
                return QBrush(Qt.green)
            else:
                return QBrush(Qt.red)

        elif role == QtCore.Qt.TextAlignmentRole:
            return QtCore.Qt.AlignCenter
        
        elif role == QtCore.Qt.ToolTipRole:
            if index.column() == 3:
                return "Number of unseen Basic Blocks reachable in N jumps"
            else:
                return None

    
    def sort(self, column, sort_order):
        self._data.sort(key=lambda x: x[column], reverse=sort_order)
        self.layoutChanged.emit()

        self._last_sort = column
        self._last_sort_order = sort_order


    def headerData(self, column, orientation, role=QtCore.Qt.DisplayRole):
        if orientation == QtCore.Qt.Horizontal:
            if role == QtCore.Qt.DisplayRole:
                return self.COLUMN_HEADERS[column]


    def rowCount(self, index):
        return len(self._data)


    def columnCount(self, index):
        if self._data:
            return len(self._data[0])
        else:
            return 0


    def setRowColor(self, index, color):
        for j in range(self.columnCount(0)):
            self.item(index, j).setBackground(color)


class JumpOverview(QWidget, DockContextHandler):
    def __init__(self, parent, name):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        font = getMonospaceFont(self)
        fm = QFontMetricsF(font)

        table_layout = QVBoxLayout()
        self.table = QTableView()
        self.table.setFont(font)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # sorting 
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSortIndicator(0, QtCore.Qt.AscendingOrder)

        data = []
        self.model = TableModel(data)
        self.table.setModel(self.model)
        table_layout.addWidget(self.table)
        
        layout = QVBoxLayout()
        layout.addLayout(table_layout)
        self.setLayout(layout)

        # init double click action
        self.table.doubleClicked.connect(self._ui_entry_double_click)
        # init right click menu
        self.ctx_menu = QMenu()
        self._action_patch = QAction("Invert Branch", None) 
        self.ctx_menu.addAction(self._action_patch)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._ui_table_ctx_menu_handler)

        self.bv = None
        self.filename = None
        self.do_sync = True


    def _ui_entry_double_click(self, index):
        self.navigate_to_addr(index)

    
    def _ui_table_ctx_menu_handler(self, pos):
        action = self.ctx_menu.exec_(self.table.viewport().mapToGlobal(pos))
        if not action:
            return
        
        rows = self.table.selectionModel().selectedRows()
        indices = [i.row() for i in rows]
        if len(indices) > 0 and action == self._action_patch:
            for i in indices:
                addr = int(self.model._data[i][0], 16)
                if self.patch(addr):
                    if not addr in self.model._patched:
                        self.model._patched.append(addr)
                    else:
                        self.model._patched.remove(addr)
                    self.model.data(rows[i], role=QtCore.Qt.BackgroundRole)
                else:
                    interaction.show_message_box("Patching Error", 
                        "This architecture does not seem to support auto-patching yet.",
                        icon=MessageBoxIcon.ErrorIcon)

    
    def navigate_to_addr(self, index):
        addr = int(self.model._data[index.row()][0], 16)
        dh = DockHandler.getActiveDockHandler()
        vf = dh.getViewFrame()
        vi = vf.getCurrentViewInterface()
        vi.navigate(addr)


    def patch(self, addr):
        if self.bv is None:
            return False
        try:
            return self.bv.invert_branch(addr)
        except:
            return False


    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            pass
        else:
            self.bv = view_frame.actionContext().binaryView
            self.filename = self.bv.file.original_filename
    

    @staticmethod
    def create_widget(name, parent, data=None):
        return JumpOverview(parent, name)


class Importer(BackgroundTaskThread):
    def __init__(self, view, file_name):
        BackgroundTaskThread.__init__(self, "...", True)
        self.view = view
        self.offset = view.start
        self.file = file_name
        self.bv =  view
        

    def run(self):
        with open(self.file, 'r') as f:
            data = []
            for l in f:
                args = l.split(' ')
                data.append(args)
                addr = int(args[0], 16)
                if "ALWAYS" in args[2]:
                    for func in self.bv.get_functions_containing(addr):
                        func.set_auto_instr_highlight(addr, colors["green"])
                else:
                    for func in self.bv.get_functions_containing(addr):
                        func.set_auto_instr_highlight(addr, colors["red"])

        for x in data:
            x[1] = x[1][10:]
            x[2] = x[2][:-6]
            x[3] = int(x[3])
        
        dock_handler = DockHandler.getActiveDockHandler()
        table = dock_handler.getDockWidget("JMPscare Overview").widget()

        table.model = TableModel(table.model._data + data)
        table.table.setModel(table.model)

        log.log(1, "[JMPscare] Successfully imported analysis data")
        

def import_data(bv):
    file_name = interaction.get_open_filename_input("Choose JMPscare analysis output file.")
    i = Importer(bv, file_name)
    i.run()
    

def openDockWidget():
    dock_handler = DockHandler.getActiveDockHandler()
    dock_handler.addDockWidget("JMPscare Overview", JumpOverview.create_widget, Qt.RightDockWidgetArea, Qt.Vertical, True)


# view.always_branch ,  view.convert_to_nop / never_branch, view.invert_branch, save
PluginCommand.register("JMPscare\\Import Data", "Import analysis data previously generated with the JMPscare anlysis tool", import_data)
openDockWidget()