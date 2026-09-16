def closeEvent(self, event):
    self.timer.stop()
    if self.client.connected:
        ok = self.client.send_packet(b"FABT")
        log_console(f"[FABT] 已发送, 结果={ok}")
    else:
        log_console("[FABT] 连接已断开，未发送")
    self.reset_transfer_state()
    # 断开信号
    try:
        self.client.signals.on_fs.disconnect(self.on_fs_data)
    except Exception:
        pass
    # 从主窗口字典删除自己
    if self.main_window and self.client in self.main_window.open_file_dialogs:
        if self.main_window.open_file_dialogs[self.client] is self:
            del self.main_window.open_file_dialogs[self.client]
    log_console(f"文件管理关闭: {self.client.display_name}")
    super().closeEvent(event)
