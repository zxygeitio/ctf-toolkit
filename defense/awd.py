#!/usr/bin/python3
"""
CTF AWD防御模块
功能: 文件完整性/Webshell扫描/WAF规则/流量分析/Flag保护/服务健康检查
用法: python3 defense.py <command> [args]
"""
import os, re, json, time, hashlib, subprocess, sqlite3
from pathlib import Path
from datetime import datetime

LOOT = "/root/ctf-toolkit/loot/defense"
os.makedirs(LOOT, exist_ok=True)

def log(msg, level="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)

# ═══════════════════════════════════════════════
# 文件完整性监控
# ═══════════════════════════════════════════════
class FileIntegrity:
    @staticmethod
    def baseline(path="/var/www", output=f"{LOOT}/baseline.json"):
        """创建文件完整性基线"""
        log(f"创建基线: {path}")
        hashes = {}
        count = 0
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in ('.git','__pycache__','node_modules','.svn')]
            for f in files:
                fpath = os.path.join(root, f)
                try:
                    h = hashlib.sha256(open(fpath,"rb").read()).hexdigest()
                    hashes[fpath] = {"hash":h, "size":os.path.getsize(fpath), "mtime":os.path.getmtime(fpath)}
                    count += 1
                except: pass
        with open(output, "w") as f: json.dump(hashes, f, indent=2)
        log(f"基线: {count} 文件 -> {output}")
        return hashes

    @staticmethod
    def check(path="/var/www", baseline=f"{LOOT}/baseline.json"):
        """检查文件变更"""
        if not os.path.exists(baseline):
            log("基线不存在,先创建", "warn")
            return FileIntegrity.baseline(path)
        with open(baseline) as f: old = json.load(f)
        added, modified, deleted = [], [], []
        current = {}
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in ('.git','__pycache__','node_modules','.svn')]
            for f in files:
                fpath = os.path.join(root, f)
                try:
                    h = hashlib.sha256(open(fpath,"rb").read()).hexdigest()
                    current[fpath] = h
                    if fpath not in old: added.append(fpath)
                    elif old[fpath]["hash"] != h: modified.append(fpath)
                except: pass
        for fpath in old:
            if fpath not in current: deleted.append(fpath)
        if added: log(f"新增 {len(added)} 文件:", "warn"); [log(f"  + {f}") for f in added[:10]]
        if modified: log(f"修改 {len(modified)} 文件:", "warn"); [log(f"  ~ {f}") for f in modified[:10]]
        if deleted: log(f"删除 {len(deleted)} 文件:", "warn"); [log(f"  - {f}") for f in deleted[:10]]
        if not added and not modified and not deleted: log("文件无变更", "ok")
        # 保存变更记录
        with open(f"{LOOT}/changes_{int(time.time())}.json","w") as f:
            json.dump({"added":added,"modified":modified,"deleted":deleted}, f, indent=2)
        return added, modified, deleted

# ═══════════════════════════════════════════════
# Webshell扫描
# ═══════════════════════════════════════════════
class WebshellScanner:
    PATTERNS = [
        (r'system\s*\(', "PHP system()"),
        (r'exec\s*\(', "PHP exec()"),
        (r'passthru\s*\(', "PHP passthru()"),
        (r'eval\s*\(\s*base64', "PHP eval(base64)"),
        (r'assert\s*\(', "PHP assert()"),
        (r'shell_exec\s*\(', "PHP shell_exec()"),
        (r'popen\s*\(', "PHP popen()"),
        (r'proc_open\s*\(', "PHP proc_open()"),
        (r'\$_GET\s*\[.*\]\s*\(', "PHP variable function"),
        (r'\$_POST\s*\[.*\]\s*\(', "PHP variable function"),
        (r'Runtime\.getRuntime\(\)\.exec', "Java Runtime.exec"),
        (r'ProcessBuilder', "Java ProcessBuilder"),
        (r'eval\s*\(', "Generic eval"),
        (r'exec\s*\(', "Generic exec"),
        (r'_\$\$ND_FUNC\$\$_', "Node.js deserialization"),
        (r'<%.*Runtime.*exec', "JSP Runtime.exec"),
        (r'cmd\.exe|/bin/sh|/bin/bash', "Shell command"),
    ]
    EXTENSIONS = (".php",".php5",".phtml",".phar",".jsp",".jspx",".asp",".aspx",".py",".rb",".pl",".cgi")

    @staticmethod
    def scan(path="/var/www", quick=False):
        """扫描Webshell"""
        log(f"Webshell扫描: {path}")
        found = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in ('.git','__pycache__','node_modules')]
            for f in files:
                if not f.endswith(WebshellScanner.EXTENSIONS): continue
                fpath = os.path.join(root, f)
                try:
                    content = open(fpath, errors="ignore").read(100000)
                    for pat, label in WebshellScanner.PATTERNS:
                        if re.search(pat, content, re.I):
                            found.append({"file":fpath, "type":label, "line":content[:200]})
                            log(f"  Webshell: {fpath} ({label})", "hit")
                            break
                    # 检查文件大小异常
                    size = os.path.getsize(fpath)
                    if size > 500000:  # >500KB的PHP文件可疑
                        log(f"  大文件: {fpath} ({size} bytes)", "warn")
                except: pass
        log(f"扫描完成: {len(found)} 个可疑文件")
        with open(f"{LOOT}/webshells.json","w") as f: json.dump(found, f, indent=2)
        return found

# ═══════════════════════════════════════════════
# WAF规则生成
# ═══════════════════════════════════════════════
class WAFGenerator:
    @staticmethod
    def generate_nginx(findings, output=f"{LOOT}/waf.conf"):
        """生成Nginx WAF规则"""
        rules = ["# CTF AWD WAF Rules - Auto Generated", f"# Generated: {datetime.now()}", ""]
        rules.append("# SQL Injection")
        rules.append("if ($args ~* \"(union|select|insert|update|delete|drop|alter|exec|concat|char|substr)\") { return 403; }")
        rules.append("if ($request_body ~* \"(union|select|insert|update|delete|drop|alter|exec|concat|char|substr)\") { return 403; }")
        rules.append("")
        rules.append("# Command Injection")
        rules.append("if ($args ~* \"(;|\\||`|\\$\\(|&&|\\|\\|)\") { return 403; }")
        rules.append("")
        rules.append("# Path Traversal")
        rules.append("if ($args ~* \"(\\.\\./|\\.\\.\\\\|/etc/passwd|/etc/shadow|/proc/)\") { return 403; }")
        rules.append("")
        rules.append("# XSS")
        rules.append("if ($args ~* \"(<script|javascript:|onerror=|onload=|onclick=)\") { return 403; }")
        rules.append("")
        rules.append("# Block sensitive paths")
        rules.append("location ~ /\\.git { deny all; }")
        rules.append("location ~ /\\.env { deny all; }")
        rules.append("location ~ /actuator { deny all; }")
        rules.append("location ~ /debug { deny all; }")
        rules.append("location ~ /console { deny all; }")
        rules.append("location ~ /phpinfo { deny all; }")
        rules.append("")
        # 根据发现的漏洞添加针对性规则
        if findings:
            rules.append("# Targeted rules based on findings")
            for f in findings:
                if hasattr(f, 'path') and f.path:
                    rules.append(f"location = {f.path} {{ deny all; }}  # {f.type}")
        with open(output, "w") as f: f.write("\n".join(rules))
        log(f"WAF规则: {output}")
        return output

    @staticmethod
    def generate_php_prepend(findings, output=f"{LOOT}/prepend.php"):
        """生成PHP prepend sanitizer"""
        code = '''<?php
// CTF AWD PHP Sanitizer - Auto Generated
// Add to php.ini: auto_prepend_file = /path/to/prepend.php

// Block common attack patterns in REQUEST_URI
$attacks = ['union select', 'into outfile', 'load_file', 'eval(', 'system(',
            'exec(', 'passthru(', 'shell_exec(', '../', '..\\\\', '/etc/passwd',
            'php://', 'data://', 'expect://'];
$uri = strtolower($_SERVER['REQUEST_URI']);
foreach ($attacks as $attack) {
    if (strpos($uri, $attack) !== false) {
        http_response_code(403);
        exit('Blocked by WAF');
    }
}
// Block suspicious POST data
if ($_POST) {
    $post = strtolower(json_encode($_POST));
    foreach (['union', 'select', 'eval(', 'system(', 'exec('] as $pat) {
        if (strpos($post, $pat) !== false) {
            http_response_code(403);
            exit('Blocked by WAF');
        }
    }
}
'''
        with open(output, "w") as f: f.write(code)
        log(f"PHP Sanitizer: {output}")
        return output

# ═══════════════════════════════════════════════
# Flag保护
# ═══════════════════════════════════════════════
class FlagProtect:
    @staticmethod
    def protect(flag_path="/flag"):
        """保护Flag文件"""
        if not os.path.exists(flag_path):
            log(f"Flag不存在: {flag_path}", "warn"); return
        # 设置不可变属性
        os.system(f"chattr +i {flag_path} 2>/dev/null")
        # 设置权限
        os.chmod(flag_path, 0o400)
        # 读取内容备份
        content = open(flag_path).read().strip()
        log(f"Flag保护: {flag_path} (chmod 400, chattr +i)")
        log(f"Flag内容: {content[:20]}...")
        # 创建蜜罐flag
        decoys = ["/tmp/flag.txt", "/var/www/flag.txt", "/home/flag.txt"]
        for d in decoys:
            try:
                with open(d, "w") as f: f.write("flag{fake_decoy_flag_" + str(int(time.time())) + "}")
                os.chmod(d, 0o644)
                log(f"  蜜罐: {d}")
            except: pass
        return content

    @staticmethod
    def monitor(flag_path="/flag"):
        """监控Flag文件访问"""
        log(f"监控Flag: {flag_path}")
        log("  使用 inotifywait -m -e access,open,modify " + flag_path)
        log("  或 auditctl -w " + flag_path + " -p rwa -k flag_access")

# ═══════════════════════════════════════════════
# 服务健康检查
# ═══════════════════════════════════════════════
class HealthCheck:
    @staticmethod
    def check(services=None):
        """检查服务状态"""
        if services is None:
            services = {"web":80, "ssh":22, "mysql":3306, "redis":6379}
        results = {}
        for name, port in services.items():
            import socket
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect(("127.0.0.1", port))
                s.close()
                results[name] = "UP"
                log(f"  {name}:{port} -> UP", "ok")
            except:
                results[name] = "DOWN"
                log(f"  {name}:{port} -> DOWN", "err")
        return results

    @staticmethod
    def check_web(url="http://127.0.0.1"):
        """检查Web服务"""
        try:
            import urllib.request
            resp = urllib.request.urlopen(url, timeout=3)
            log(f"Web {url} -> {resp.getcode()}", "ok")
            return True
        except Exception as e:
            log(f"Web {url} -> {e}", "err")
            return False

# ═══════════════════════════════════════════════
# 流量分析
# ═══════════════════════════════════════════════
class TrafficAnalyzer:
    @staticmethod
    def analyze_logs(logfile="/var/log/apache2/access.log"):
        """分析访问日志提取攻击payload"""
        if not os.path.exists(logfile):
            log(f"日志不存在: {logfile}", "warn"); return []
        attacks = []
        patterns = [
            (r"union.*select", "SQLi"),
            (r"\.\./\.\./", "LFI"),
            (r"<script", "XSS"),
            (r";\s*id|;\s*cat|;\s*ls", "CMDi"),
            (r"flag\{", "Flag泄露"),
            (r"/actuator", "Actuator探测"),
            (r"/\.git", "Git泄露探测"),
            (r"/admin", "Admin探测"),
        ]
        with open(logfile, errors="ignore") as f:
            for line in f:
                for pat, label in patterns:
                    if re.search(pat, line, re.I):
                        ip = line.split()[0] if line.split() else "?"
                        attacks.append({"ip":ip, "type":label, "line":line.strip()[:200]})
                        break
        log(f"日志分析: {len(attacks)} 条攻击")
        # 统计
        by_type = {}
        for a in attacks: by_type[a["type"]] = by_type.get(a["type"],0)+1
        for t,c in sorted(by_type.items(), key=lambda x:-x[1]):
            log(f"  {t}: {c}")
        with open(f"{LOOT}/attacks.json","w") as f: json.dump(attacks, f, indent=2, ensure_ascii=False)
        return attacks

    @staticmethod
    def extract_exploits(logfile="/var/log/apache2/access.log"):
        """从日志提取对手的exploit payload"""
        attacks = TrafficAnalyzer.analyze_logs(logfile)
        exploits = []
        for a in attacks:
            if a["type"] in ("SQLi","CMDi","LFI","XSS"):
                exploits.append(a["line"])
        if exploits:
            log(f"提取到 {len(exploits)} 个exploit payload")
            with open(f"{LOOT}/exploit_payloads.txt","w") as f:
                f.write("\n".join(exploits))
        return exploits

# ═══════════════════════════════════════════════
# 凭证加固
# ═══════════════════════════════════════════════
class CredentialHardening:
    @staticmethod
    def rotate_mysql():
        """修改MySQL密码"""
        import random, string
        new_pass = ''.join(random.choices(string.ascii_letters+string.digits, k=16))
        os.system(f"mysql -u root -e \"ALTER USER 'root'@'localhost' IDENTIFIED BY '{new_pass}';\" 2>/dev/null")
        log(f"MySQL root密码已修改: {new_pass}")
        return new_pass

    @staticmethod
    def rotate_redis():
        """修改Redis密码"""
        import random, string
        new_pass = ''.join(random.choices(string.ascii_letters+string.digits, k=16))
        os.system(f"redis-cli CONFIG SET requirepass '{new_pass}' 2>/dev/null")
        log(f"Redis密码已设置: {new_pass}")
        return new_pass

    @staticmethod
    def disable_services():
        """禁用不必要的服务"""
        for svc in ["telnet","ftp","rsh","rlogin","tftp"]:
            os.system(f"systemctl stop {svc} 2>/dev/null; systemctl disable {svc} 2>/dev/null")
            log(f"禁用: {svc}")

# ═══════════════════════════════════════════════
# CLI入口
# ═══════════════════════════════════════════════
def main():
    import sys
    if len(sys.argv) < 2:
        print("CTF AWD防御模块")
        print("用法:")
        print("  python3 defense.py baseline [path]     创建文件基线")
        print("  python3 defense.py check [path]        检查文件变更")
        print("  python3 defense.py webshell [path]     扫描Webshell")
        print("  python3 defense.py waf                 生成WAF规则")
        print("  python3 defense.py flag [path]         保护Flag")
        print("  python3 defense.py health              服务健康检查")
        print("  python3 defense.py traffic [logfile]   流量分析")
        print("  python3 defense.py harden              凭证加固")
        print("  python3 defense.py all                 全部防御")
        return

    cmd = sys.argv[1]
    if cmd == "baseline": FileIntegrity.baseline(sys.argv[2] if len(sys.argv)>2 else "/var/www")
    elif cmd == "check": FileIntegrity.check(sys.argv[2] if len(sys.argv)>2 else "/var/www")
    elif cmd == "webshell": WebshellScanner.scan(sys.argv[2] if len(sys.argv)>2 else "/var/www")
    elif cmd == "waf": WAFGenerator.generate_nginx([]); WAFGenerator.generate_php_prepend([])
    elif cmd == "flag": FlagProtect.protect(sys.argv[2] if len(sys.argv)>2 else "/flag")
    elif cmd == "health": HealthCheck.check()
    elif cmd == "traffic": TrafficAnalyzer.analyze_logs(sys.argv[2] if len(sys.argv)>2 else "/var/log/apache2/access.log")
    elif cmd == "harden": CredentialHardening.rotate_mysql(); CredentialHardening.rotate_redis()
    elif cmd == "all":
        log("=== 全部防御 ===")
        FlagProtect.protect()
        FileIntegrity.baseline()
        WebshellScanner.scan()
        WAFGenerator.generate_nginx([])
        WAFGenerator.generate_php_prepend([])
        HealthCheck.check()
        log("=== 防御完成 ===")
    else: print(f"未知命令: {cmd}")

if __name__ == "__main__": main()
