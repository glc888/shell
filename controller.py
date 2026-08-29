import sys
import socket
import threading
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QListView, QTextEdit,
                             QMenu, QInputDialog, QAbstractItemView)
from PyQt6.QtCore import Qt, QAbstractListModel, QVariant, QModelIndex

class ClientSession:
    def __init__(self, conn: socket.socket, addr):
        self.conn = conn
        self.addr = addr
        self.ip_str = f"{addr[0]}:{addr[1]}"
        self.last_pong = datetime.now()
        self.connected = True

    def send(self, data: bytes) -> bool:
        if not self.connected:
            return False
        try:
            self.conn.sendall(data)
            return True
        except (OSError, BrokenPipeError, ConnectionResetError):
            self.close()
            return False

    def close(self):
        self.connected = False
        try:
            self.conn.close()
        except Exception:
            pass


class ClientListModel(QAbstractListModel):
    def __init__(self):
        super().__init__()
        self.items: list[ClientSession] = []

    def rowCount(self, parent=QModelIndex()):
        return len(self.items)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return QVariant()
        s = self.items[index.row()]
        return QVariant(s.ip_str)

    def add(self, sess: ClientSession):
        self.beginInsertRows(QModelIndex(), len(self.items), len(self.items))
        self.items.append(sess)
        self.endInsertRows()

    def remove_by_obj(self, sess: ClientSession):
        idx = self.items.index(sess)
        self.beginRemoveRows(QModelIndex(), idx, idx)
        self.items.pop(idx)
        self.endRemoveRows()


class MainWindow(QMainWindow):
    defMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TCP Controller")
        self.resize(650, 480)
        self.server_sock: socket.socket | None = None
        self.server_running = False
        self.client_model = ClientListModel()

        w = QWidget()
        self.setCentralWidget(w)
        lay = QVBoxLayout(w)

        top_lay = QHBoxLayout()
        top_lay.addWidget(QLabel("端口"))
        self.port_edit = QLineEdit("8888")
        top_lay.addWidget(self.port_edit)
        self.btn_start = QPushButton("启动监听")
        self.btn_start.clicked.connect(self.start_server)
        top_lay.addWidget(self.btn_start)
        self.btn_stop = QPushButton("停止监听")
        self.btn_stop.clicked.connect(self.stop_server)
        self.btn_stop.setEnabled(False)
        top_lay.addWidget(self.btn_stop)
        lay.addLayout(top_lay)

        self.view = QListView()
        self.view.setModel(self.client_model)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self.on_context_menu)
        lay.addWidget(self.view)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        lay.addWidget(self.log_box)

    def log(self, msg):
        self.log_box.append(f"{datetime.now().strftime('%H:%M:%S')} {msg}")

    def accept_loop(self):
        while self.server_running:
            try:
                conn, addr = self.server_sock.accept()
                sess = ClientSession(conn, addr)
                self.client_model.add(sess)
                self.log(f"客户端接入 {sess.ip_str}")
                t = threading.Thread(target=self.client_recv, args=(sess,), daemon=True)
                t.start()
            except OSError:
                break

    def client_recv(self, sess: ClientSession):
        buf = bytearray()
        while sess.connected:
            try:
                chunk = sess.conn.recv(1024)
                if not chunk:
                    break
                buf.extend(chunk)
            except OSError:
                break
        sess.close()
        self.client_model.remove_by_obj(sess)
        self.log(f"客户端断开 {sess.ip_str}")

    def start_server(self):
        port = int(self.port_edit.text())
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("0.0.0.0", port))
        self.server_sock.listen(8)
        self.server_running = True
        threading.Thread(target=self.accept_loop, daemon=True).start()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.log(f"已启动监听端口 {port}")

    def stop_server(self):
        self.server_running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        # 关闭全部客户端，解除recv阻塞
        for s in self.client_model.items:
            s.close()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.log("已停止监听")

    def on_context_menu(self, pos):
        idx = self.view.indexAt(pos)
        if not idx.isValid():
            return
        sess: ClientSession = self.client_model.items[idx.row()]
        menu = QMenu()
        act_send = menu.addAction("发送指令")
        act = menu.exec(self.view.viewport().mapToGlobal(pos))
        if act == act_send:
            text, ok = QInputDialog.getText(self, "发送", "输入指令:")
            if ok and text:
                def worker(s: ClientSession, payload: bytes):
                    ok_ret = s.send(payload)
                    self.log(f"发送 {'成功' if ok_ret else '失败'} -> {s.ip_str}")
                threading.Thread(target=worker, args=(sess, text.encode("utf‑8")), daemon=True).start()

    def closeEvent(self, event):
        # 窗口关闭，执行和停止监听一样逻辑
        self.stop_server()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
