from binaryninja import *
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, getMonospaceFont
from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractTableModel
from PySide2.QtWidgets import *
from PySide2.QtGui import (QFont, QFontMetricsF, QTextCursor)

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


    def data(self, index, role=QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole:
            column = index.column()
            return self._data[index.row()][index.column()]


    def rowCount(self, index):
        return len(self._data)


    def columnCount(self, index):
        if self._data:
            return len(self._data[0])
        else:
            return 0


class TableView(QWidget, DockContextHandler):
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
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSortIndicator(0, QtCore.Qt.AscendingOrder)

        data = []
        self.model = TableModel(data)
        self.table.setModel(self.model)
        table_layout.addWidget(self.table)
        
        # Putting all the child layouts together
        layout = QVBoxLayout()
        layout.addLayout(table_layout)
        # layout.addLayout(footer_layout)
        self.setLayout(layout)

        self.bv = None
        self.filename = None
        self.do_sync = True


    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            pass
        else:
            self.bv = view_frame.actionContext().binaryView
            self.filename = self.bv.file.original_filename
    

    @staticmethod
    def create_widget(name, parent, data=None):
        return TableView(parent, name)


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
        
        dock_handler = DockHandler.getActiveDockHandler()
        table = dock_handler.getDockWidget("JXMPscare Overview").widget()

        table.model = TableModel(data)
        table.table.setModel(table.model)

        log.log(1, "[JXMPscare] Successfully imported analysis data")
        

def import_data(bv):
    file_name = interaction.get_open_filename_input("Choose JXMPscare analysis output file.")
    i = Importer(bv, file_name)
    i.run()
    

def openDockWidget():
    # mw = QApplication.allWidgets()[0].window()
    # dock_handler = mw.findChild(DockHandler, '__DockHandler')
    dock_handler = DockHandler.getActiveDockHandler()
    dock_handler.addDockWidget("JXMPscare Overview", TableView.create_widget, Qt.RightDockWidgetArea, Qt.Vertical, True)

# view.always_branch ,  view.convert_to_nop / never_branch, view.invert_branch, save
PluginCommand.register("JXMPscare\\Import Data", "Import analysis data previously generated with the JXMPscare anlysis tool", import_data)
openDockWidget()