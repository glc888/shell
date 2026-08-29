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
        self.status = "connected"

    def send(self, data: bytes):
        if self.status != "connected":
            return False
        try:
            self.conn.sendall(data)
            return True
        except (OSError, BrokenPipeError, ConnectionResetError):
            self.close()
            return False
        except Exception:
            self.close()
            return False

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
        self.status = "disconnected"

class ClientListModel(QAbstractListModel):
    def __init__(self):
        super().__init__()
        self.clients: list[ClientSession] = []

    def rowCount(self, parent=QModelIndex()):
        return len(self.clients)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return QVariant()
        c = self.clients[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return QVariant(f"{c.ip_str} | last_pong:{c.last_pong.strftime('%H:%M:%S')} | {c.status}")
        return QVariant()

    def add(self, sess: ClientSession):
        self.beginInsertRows(QModelIndex(), len(self.clients), len(self.clients))
        self.clients.append(sess)
        self.endInsertRows()

    def remove_by_obj(self, sess: ClientSession):
        idx = self.clients.index(sess)
        self.beginRemoveRows(QModelIndex(), idx, idx)
        self.clients.pop(idx)
        self.endRemoveRows()

class MainWin(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TCP反向控制端 Python‑PyQt6")
        self.resize(680, 420)
        self.server_sock = None
        self.listen_thread = None
        self.running = False
        self.model = ClientListModel()

        cw = QWidget()
        self.setCentralWidget(cw)
        lay = QVBoxLayout(cw)

        top_lay = QHBoxLayout()
        top_lay.addWidget(QLabel("监听端口:"))
        self.port_edit = QLineEdit("8888")
        self.port_edit.setFixedWidth(80)
        top_lay.addWidget(self.port_edit)
        self.btn_start = QPushButton("启动监听")
        self.btn_start.clicked.connect(self.on_start)
        top_lay.addWidget(self.btn_start)
        self.btn_stop = QPushButton("停止监听")
        self.btn_stop.clicked.connect(self.on_stop)
        self.btn_stop.setEnabled(False)
        top_lay.addWidget(self.btn_stop)
        lay.addLayout(top_lay)

        self.list_view = QListView()
        self.list_view.setModel(self.model)
        self.list_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.list_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.list_view.customContextMenuRequested.connect(self.show_right_menu)
        lay.addWidget(self.list_view)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        lay.addWidget(self.log_text)

    def log(self, msg):
        t = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{t}] {msg}")

    def accept_loop(self):
        while self.running:
            try:
                conn, addr = self.server_sock.accept()
                sess = ClientSession(conn, addr)
                self.log(f"新被控端接入 {sess.ip_str}")
                self.model.add(sess)
                th = threading.Thread(target=self.client_recv_loop, args=(sess,), daemon=True)
                th.start()
            except Exception:
                break

    def client_recv_loop(self, sess: ClientSession):
        buf = bytearray()
        while True:
            try:
                data = sess.conn.recv(1024)
                if not data:
                    break
                buf.extend(data)
                if b'\x00' in buf:
                    parts = buf.split(b'\x00')
                    for part in parts[:-1]:
                        txt = part.decode("ascii", errors="ignore")
                        if txt == "PONG":
                            sess.last_pong = datetime.now()
                            self.log(f"收到PONG from {sess.ip_str}")
                    buf = parts[-1]
            except Exception:
                break
        sess.close()
        self.log(f"被控端断开 {sess.ip_str}")
        idx = -1
        for i,item in enumerate(self.model.clients):
            if item is sess:
                idx = i
                break
        if idx != -1:
            self.model.remove_by_obj(sess)

    def show_right_menu(self, pos):
        index = self.list_view.indexAt(pos)
        if not index.isValid():
            return
        sess: ClientSession = self.model.clients[index.row()]
        menu = QMenu(self)
        act_ping = menu.addAction("发送 PING")
        act_cmd = menu.addAction("下发自定义指令")
        act_close = menu.addAction("断开连接")
        action = menu.exec(self.list_view.viewport().mapToGlobal(pos))

        def _send_worker(s: ClientSession, payload: bytes, ok_msg: str, fail_msg: str):
            try:
                ret = s.send(payload)
                if ret:
                    self.log(ok_msg)
                else:
                    self.log(fail_msg)
            except Exception as e:
                self.log(f"发送异常: {repr(e)}")

        if action == act_ping:
            threading.Thread(
                target=_send_worker,
                args=(sess, b"PING", f"向 {sess.ip_str} 发送PING", f"向 {sess.ip_str} 发送PING失败，连接失效"),
                daemon=True
            ).start()

        elif action == act_cmd:
            text, ok_dialog = QInputDialog.getText(self, "下发指令", "输入指令内容:")
            if ok_dialog and text:
                payload_bytes = text.encode("ascii")
                threading.Thread(
                    target=_send_worker,
                    args=(sess, payload_bytes, f"下发指令: {text} → {sess.ip_str}", f"下发指令失败 → {sess.ip_str}，socket失效"),
                    daemon=True
                ).start()

        elif action == act_close:
            try:
                sess.close()
                self.log(f"主动断开 {sess.ip_str}")
            except Exception:
                pass

    def on_start(self):
        port = int(self.port_edit.text())
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("127.0.0.1", port))
        self.server_sock.listen(8)
        self.running = True
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.log(f"开始监听端口 {port}")
        self.listen_thread = threading.Thread(target=self.accept_loop, daemon=True)
        self.listen_thread.start()

    def on_stop(self):
        self.running = False
        if self.server_sock:
            self.server_sock.close()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.log("停止监听")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MainWin()
    w.show()
    sys.exit(app.exec())
