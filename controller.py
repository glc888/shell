import sys

# ========== 【全局只允许import，禁止任何会抛异常的执行代码！！】 ==========

def main():
    import os
    import ctypes

    # 获取exe所在目录，打包环境有效
    exe_dir = os.path.dirname(sys.executable)

    # 加载DLL
    dll_path = os.path.join(exe_dir, "blob2pem.dll")
    lib = ctypes.CDLL(dll_path)

    # 读取密钥文件
    priv_key_path = os.path.join(exe_dir, "c2_private.key")
    pub_key_path = os.path.join(exe_dir, "c2_public.key")

    with open(priv_key_path, "rb") as f:
        priv_data = f.read()
    with open(pub_key_path, "rb") as f:
        pub_data = f.read()

    # ==================== 这里粘贴你原本全部业务/GUI代码 ====================


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        exe_dir = os.path.dirname(sys.executable)
        log_path = os.path.join(exe_dir, "crash.log")
        with open(log_path, "w", encoding="utf-8") as fp:
            fp.write(traceback.format_exc())
