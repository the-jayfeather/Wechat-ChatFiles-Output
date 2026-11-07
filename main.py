"""微信聊天记录导出器 —— GUI 入口。

用法：
  python main.py                 # 图形界面
  python main.py --cli <账号> <输出目录>   # 命令行（调试用）
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import queue
import shutil
import sys
import tempfile
import threading
import traceback

import wxcore
import wxexport

APP_NAME = "微信聊天记录导出器"
APP_VER = "1.0"


def resource(rel: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024


def run_export(accounts, outbase, log=print, mode="append"):
    pids = wxcore.weixin_pids()
    if not pids:
        log("未检测到微信进程，请先登录微信再导出。")
        return []
    log(f"检测到微信进程：{pids}")

    image_key = wxcore.load_cached_image_key()
    if image_key:
        log("使用上次缓存的图片密钥")
    else:
        try:
            image_key = wxcore.find_image_key(accounts[0]["dir"], pids, log)
            if image_key:
                wxcore.save_image_key(image_key)
        except Exception as e:
            log(f"图片密钥扫描失败：{e}")

    done = []
    for acc in accounts:
        log(f"\n===== 账号 {acc['id']} =====")
        outdir = os.path.join(outbase, f"微信记录_{acc['id']}")
        merge_old = None
        if os.path.isdir(outdir):
            jp = os.path.join(outdir, "data.json")
            if mode == "overwrite":
                log(" 覆盖模式：删除旧导出…")
                shutil.rmtree(outdir, ignore_errors=True)
                os.makedirs(outdir, exist_ok=True)
            elif os.path.exists(jp):
                try:
                    merge_old = json.load(open(jp, encoding="utf-8"))
                    log(f" 补充模式：读取已有导出（{len(merge_old.get('conversations') or [])} 个会话）")
                except Exception:
                    merge_old = None
        os.makedirs(outdir, exist_ok=True)
        work = tempfile.mkdtemp(prefix="wxexp_")
        try:
            log(" 扫描数据库密钥（只读进程内存，约 30-60 秒）…")
            dec, keys = wxexport.decrypt_account(acc, work, log)
            if not dec:
                log(" 解密失败：没有拿到密钥。请确认微信已登录、且没有被安全软件拦截。")
                continue
            log(f" 解密完成，获得 {len(keys)} 个库密钥")
            data = wxexport.build_export(acc, dec, outdir, image_key, log, merge_old=merge_old)
            src = resource(os.path.join("assets", "viewer.html"))
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(outdir, "聊天记录.html"))
            with open(os.path.join(outdir, "导出说明.txt"), "w", encoding="utf-8") as f:
                f.write(f"{APP_NAME} v{APP_VER}\n"
                        f"账号：{data['account']}\n"
                        f"导出时间：{data['generated']}\n"
                        f"会话：{len(data['conversations'])}　消息：{sum(c['count'] for c in data['conversations'])}\n\n"
                        "双击「聊天记录.html」即可查看；所有数据都在本地，不联网。\n"
                        "注意：本文件夹含个人隐私，请勿上传或分享。\n")
            log(f" 已导出到：{outdir}")
            done.append(outdir)
        except Exception:
            log(" 出错：\n" + traceback.format_exc())
        finally:
            shutil.rmtree(work, ignore_errors=True)
    log(f"\n完成，共 {len(done)} 个账号。")
    return done


# ---------------- GUI ----------------
def ask_mode(parent, paths):
    """已有导出时的选择框：返回 append / overwrite / None。"""
    import tkinter as tk
    from tkinter import ttk

    dlg = tk.Toplevel(parent)
    dlg.title("检测到已有导出")
    dlg.transient(parent)
    dlg.resizable(False, False)
    dlg.grab_set()

    text = "以下目录已有聊天记录：\n" + "\n".join("  " + p for p in paths[:6])
    if len(paths) > 6:
        text += f"\n  ……共 {len(paths)} 个"
    tk.Label(dlg, text=text, justify="left").pack(padx=18, pady=(16, 10))

    v = tk.StringVar(value="append")
    ttk.Radiobutton(dlg, text="补充模式（默认）：保留已有文件，只追加新消息，保留手动匹配的内容",
                    variable=v, value="append").pack(anchor="w", padx=18)
    ttk.Radiobutton(dlg, text="覆盖模式：删除旧导出，从头开始",
                    variable=v, value="overwrite").pack(anchor="w", padx=18, pady=(4, 12))

    res = {"v": None}
    bar = tk.Frame(dlg)
    bar.pack(fill="x", padx=18, pady=(0, 16))
    ttk.Button(bar, text="确定", command=lambda: (res.update(v=v.get()), dlg.destroy())).pack(side="right")
    ttk.Button(bar, text="取消", command=dlg.destroy).pack(side="right", padx=8)

    dlg.update_idletasks()
    dlg.geometry(f"+{parent.winfo_rootx() + 140}+{parent.winfo_rooty() + 140}")
    dlg.wait_window()
    return res["v"]


def main_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title(f"{APP_NAME} v{APP_VER}")
    root.geometry("880x620")
    root.minsize(760, 520)

    q = queue.Queue()
    state = {"accounts": [], "root": None}

    top = ttk.Frame(root, padding=10)
    top.pack(fill="x")
    status = tk.StringVar(value="正在检测…")
    ttk.Label(top, textvariable=status, font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w")
    pathvar = tk.StringVar(value="")
    ttk.Label(top, textvariable=pathvar, foreground="#666").pack(anchor="w")

    mid = ttk.Frame(root, padding=(10, 0))
    mid.pack(fill="both", expand=True)
    cols = ("id", "size", "mtime", "msg")
    tv = ttk.Treeview(mid, columns=cols, show="headings", selectmode="extended", height=8)
    for c, t, w in (("id", "账号", 300), ("size", "数据量", 110), ("mtime", "最近活动", 150), ("msg", "消息库", 90)):
        tv.heading(c, text=t)
        tv.column(c, width=w, anchor="w")
    tv.pack(side="left", fill="both", expand=True)
    sb = ttk.Scrollbar(mid, orient="vertical", command=tv.yview)
    sb.pack(side="left", fill="y")
    tv.configure(yscrollcommand=sb.set)

    btns = ttk.Frame(root, padding=10)
    btns.pack(fill="x")
    outvar = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Desktop", "微信导出"))

    def refresh():
        state["root"] = wxcore.data_root()
        accs = wxcore.list_accounts(state["root"])
        state["accounts"] = accs
        tv.delete(*tv.get_children())
        for a in accs:
            tv.insert("", "end", values=(a["id"], human(a["size"]),
                                         datetime.datetime.fromtimestamp(a["mtime"]).strftime("%Y-%m-%d %H:%M")
                                         if a["mtime"] else "-",
                                         "有" if a["has_msg"] else "无"))
        pids = wxcore.weixin_pids()
        status.set(("微信运行中" if pids else "⚠ 微信未运行（无法取密钥）") + f" · 发现 {len(accs)} 个本地账号")
        pathvar.set(f"数据目录：{state['root'] or '未找到'}")

    def pick_out():
        d = filedialog.askdirectory(initialdir=os.path.dirname(outvar.get()) or os.path.expanduser("~"))
        if d:
            outvar.set(d)

    def start(all_acc=False):
        sel = [a for a in state["accounts"] if a["id"] in
               [tv.item(i, "values")[0] for i in tv.selection()]]
        if all_acc:
            sel = state["accounts"]
        if not sel:
            messagebox.showinfo(APP_NAME, "请先在列表里选中账号（可按住 Ctrl 多选）")
            return
        if not wxcore.weixin_pids():
            messagebox.showwarning(APP_NAME, "微信没有运行。请先登录微信，再点导出。")
            return
        out = outvar.get()
        os.makedirs(out, exist_ok=True)

        existing = [os.path.join(out, f"微信记录_{a['id']}") for a in sel]
        existing = [p for p in existing if os.path.exists(os.path.join(p, "data.json"))]
        mode = "append"
        if existing:
            mode = ask_mode(root, existing)
            if not mode:
                return

        log.delete("1.0", "end")
        btn_export.config(state="disabled")
        btn_all.config(state="disabled")

        def worker():
            try:
                run_export(sel, out, lambda m: q.put(("log", m)), mode=mode)
            except Exception:
                q.put(("log", traceback.format_exc()))
            finally:
                q.put(("done", None))

        threading.Thread(target=worker, daemon=True).start()

    def poll():
        try:
            while True:
                kind, msg = q.get_nowait()
                if kind == "log":
                    log.insert("end", msg + "\n")
                    log.see("end")
                elif kind == "done":
                    btn_export.config(state="normal")
                    btn_all.config(state="normal")
                    messagebox.showinfo(APP_NAME, "导出完成，详见日志。")
        except queue.Empty:
            pass
        root.after(150, poll)

    ttk.Button(btns, text="刷新账号", command=refresh).pack(side="left")
    ttk.Button(btns, text="选择输出目录", command=pick_out).pack(side="left", padx=6)
    ttk.Entry(btns, textvariable=outvar, width=38).pack(side="left", padx=6)
    btn_all = ttk.Button(btns, text="导出全部", command=lambda: start(True))
    btn_all.pack(side="right")
    btn_export = ttk.Button(btns, text="导出选中", command=lambda: start(False))
    btn_export.pack(side="right", padx=6)

    log = tk.Text(root, height=12, bg="#111", fg="#ddd", insertbackground="#ddd",
                  font=("Consolas", 9), wrap="word")
    log.pack(fill="both", expand=False, padx=10, pady=(0, 10))

    refresh()
    root.after(150, poll)
    root.mainloop()


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--cli", nargs=2, metavar=("账号", "输出目录"))
    ap.add_argument("--list", action="store_true", help="以 JSON 输出本机账号列表")
    ap.add_argument("--mode", choices=["append", "overwrite"], default="append",
                    help="已存在导出时的处理方式，默认 append（补充）")
    args = ap.parse_args()
    if args.list:
        accs = wxcore.list_accounts(wxcore.data_root())
        print(json.dumps({
            "running": bool(wxcore.weixin_pids()),
            "root": wxcore.data_root(),
            "accounts": [{"id": a["id"], "size": a["size"], "mtime": a["mtime"]} for a in accs],
        }, ensure_ascii=False))
        return 0
    if args.cli:
        acc_id, out = args.cli
        root = wxcore.data_root()
        accs = [a for a in wxcore.list_accounts(root) if a["id"] == acc_id]
        if not accs:
            print("找不到账号", acc_id)
            return 1
        run_export(accs, out, mode=args.mode)
        return 0
    main_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main())
