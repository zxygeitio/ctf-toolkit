#!/usr/bin/python3
"""
CTF综合靶场 v2 — 模拟真实CTF比赛场景
包含: Web/Crypto/Forensics/API/认证/存储 全类型漏洞
端口: 7777
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
import os, re, json, sqlite3, subprocess, hashlib, base64, time, hmac, struct, random

DB = "/tmp/ctf_range.db"
FLAG_WEB   = "flag{w3b_vuln_m4st3r_2024}"
FLAG_SQLI  = "flag{sql_1nj3ct10n_pwn3d}"
FLAG_RCE   = "flag{rce_c0mmand_3x3cut10n}"
FLAG_LFI   = "flag{lf1_f1l3_r34d3r}"
FLAG_SSTI  = "flag{sst1_t3mpl4t3_1nj3ct10n}"
FLAG_XSS   = "flag{cr0ss_s1t3_scr1pt1ng}"
FLAG_IDOR  = "flag{1d0r_1ns3cur3_d1r3ct_0bj3ct}"
FLAG_AUTH  = "flag{4uth_byp4ss_3sc4l4t10n}"
FLAG_CSRF  = "flag{csrf_cr0ss_s1t3_r3qu3st}"
FLAG_SSRF  = "flag{ssrf_s3rv3r_s1d3_r3qu3st}"
FLAG_XXE   = "flag{xx3_xm1_3xt3rn4l_3nt1t}"
FLAG_DESER = "flag{d3s3r14l1z4t10n_rce}"
FLAG_REDIS = "flag{r3d1s_un4uth_pr1v3sc}"
FLAG_CRYPTO= "flag{crypt0_w34k_3ncrypt10n}"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT,password TEXT,role TEXT,email TEXT,token TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS secrets(id INTEGER PRIMARY KEY,user_id TEXT,key TEXT,value TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS flag(id INTEGER PRIMARY KEY,value TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,name TEXT,price TEXT,description TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,user_id TEXT,product TEXT,amount TEXT)")
    c.execute("DELETE FROM users"); c.execute("DELETE FROM secrets"); c.execute("DELETE FROM flag")
    c.execute("DELETE FROM products"); c.execute("DELETE FROM orders")
    c.execute("INSERT INTO users VALUES(1,'admin','admin123','admin','admin@ctf.lab','admintoken123')")
    c.execute("INSERT INTO users VALUES(2,'user1','pass1','user','user1@ctf.lab','usertoken456')")
    c.execute("INSERT INTO users VALUES(3,'user2','pass2','user','user2@ctf.lab','usertoken789')")
    c.execute("INSERT INTO users VALUES(4,'guest','guest','viewer','guest@ctf.lab','guesttoken')")
    c.execute("INSERT INTO secrets VALUES(1,'admin','api_key','sk-admin-FLAG_HERE')")
    c.execute("INSERT INTO secrets VALUES(2,'user1','api_key','sk-user1-abc123')")
    c.execute("INSERT INTO secrets VALUES(3,'1','db_pass','Sup3rS3cretDB!')")
    c.execute("INSERT INTO flag VALUES(1,'%s')" % FLAG_WEB)
    c.execute("INSERT INTO flag VALUES(2,'%s')" % FLAG_SQLI)
    c.execute("INSERT INTO products VALUES(1,'Secret Flag','0','The flag is hidden here: %s')" % FLAG_WEB)
    c.execute("INSERT INTO products VALUES(2,'Normal Item','10','A regular item')")
    c.execute("INSERT INTO orders VALUES(1,'1','Secret Flag','1')")
    c.execute("INSERT INTO orders VALUES(2,'2','Normal Item','3')")
    conn.commit(); conn.close()
    # 文件flag
    for path,content in [
        ("/tmp/flag.txt", FLAG_WEB), ("/tmp/flag", FLAG_WEB),
        ("/tmp/secret_flag.txt", FLAG_RCE), ("/tmp/.hidden_flag", FLAG_LFI),
    ]:
        with open(path,"w") as f: f.write(content)
    os.environ["CTF_FLAG"] = FLAG_WEB
    os.environ["SECRET_KEY"] = "super_secret_key_12345"
    os.environ["DB_PASSWORD"] = "root:password123@localhost"
    os.environ["API_KEY"] = "ak-" + FLAG_AUTH

init_db()

# HTML模板
def page(title, body, nav=True):
    nav_html = '''
    <nav style="background:#1a1a2e;padding:10px;border-bottom:2px solid #e94560">
    <a style="color:#0f3;margin:0 10px" href="/">Home</a>
    <a style="color:#0f3;margin:0 10px" href="/login">Login</a>
    <a style="color:#0f3;margin:0 10px" href="/search">Search</a>
    <a style="color:#0f3;margin:0 10px" href="/api/users">API</a>
    <a style="color:#0f3;margin:0 10px" href="/upload">Upload</a>
    <a style="color:#0f3;margin:0 10px" href="/admin">Admin</a>
    <a style="color:#0f3;margin:0 10px" href="/ping">Ping</a>
    <a style="color:#0f3;margin:0 10px" href="/render">Template</a>
    <a style="color:#0f3;margin:0 10px" href="/notes">Notes</a>
    <a style="color:#0f3;margin:0 10px" href="/tools">Tools</a>
    <a style="color:#0f3;margin:0 10px" href="/crypto">Crypto</a>
    </nav>''' if nav else ''
    return f'''<!DOCTYPE html><html><head><title>{title}</title>
    <style>body{{font-family:monospace;background:#0f0f23;color:#eee;padding:20px;max-width:900px;margin:auto}}
    a{{color:#0f3}}input,textarea,select{{background:#1a1a2e;color:#eee;border:1px solid #333;padding:6px;margin:4px}}
    pre{{background:#1a1a2e;padding:10px;border:1px solid #333;overflow-x:auto}}
    h1{{color:#e94560}}h2{{color:#0f3}}.vuln{{border:1px solid #e94560;padding:10px;margin:8px 0;border-radius:4px}}
    table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #333;padding:6px;text-align:left}}
    </style></head><body>{nav_html}<h1>{title}</h1>{body}</body></html>'''

class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def _send(self, body, code=200, ct="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Server", "Apache/2.4.41")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        if "cookie" not in str(self.headers).lower():
            self.send_header("Set-Cookie", "PHPSESSID=abc123; path=/")
        self.end_headers()
        if isinstance(body, str): body = body.encode()
        self.wfile.write(body)

    def _get_params(self):
        return parse_qs(urlparse(self.path).query)

    def _get_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode() if length else ""

    def do_GET(self):
        p = urlparse(self.path)
        path = p.path
        q = self._get_params()

        routes = {
            "/": self._home, "/login": self._login_page, "/search": self._search,
            "/ping": self._ping_page, "/render": self._render_page, "/notes": self._notes,
            "/tools": self._tools, "/crypto": self._crypto, "/upload": self._upload_page,
            "/admin": self._admin, "/api/users": self._api_users, "/api/user": self._api_user,
            "/api/secrets": self._api_secrets, "/api/orders": self._api_orders,
            "/api/config": self._api_config, "/api/health": self._api_health,
            "/robots.txt": lambda: self._send("User-agent: *\nDisallow: /admin\nDisallow: /flag.txt\nDisallow: /.git/\nDisallow: /api/secrets\nDisallow: /api/config"),
            "/sitemap.xml": lambda: self._send('<?xml version="1.0"?><urlset><url><loc>http://target/</loc></url><url><loc>http://target/login</loc></url><url><loc>http://target/admin</loc></url></urlset>', ct="text/xml"),
            "/.git/HEAD": lambda: self._send("ref: refs/heads/main"),
            "/.git/config": lambda: self._send("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://gitlab.internal/repo.git\n\tpassword = gitlab_admin_2024"),
            "/.env": lambda: self._send("DB_HOST=localhost\nDB_USER=root\nDB_PASS=SuperSecret123!\nSECRET_KEY=myflasksecret\nAPI_TOKEN=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.flag\nREDIS_URL=redis://127.0.0.1:6379"),
            "/flag.txt": lambda: self._send(FLAG_WEB), "/flag": lambda: self._send(FLAG_WEB),
            "/actuator/env": lambda: self._send(json.dumps({"db_password":"SuperSecret123!","api_key":"sk-123...cdef","secret":FLAG_WEB,"redis":{"host":"127.0.0.1","port":6379}})),
            "/actuator/heapdump": lambda: self._send("Binary heap dump (simulated) containing: " + FLAG_WEB),
            "/swagger-ui.html": lambda: self._send(page("Swagger UI", "<p>API Documentation</p><p>Endpoints: /api/users, /api/secrets, /api/orders, /api/config</p>")),
            "/graphql": lambda: self._handle_graphql(q),
            "/debug": lambda: self._send(page("Debug", f"<pre>Server: Apache/2.4.41\nPHP: 7.4.3\nPython: 3.11\nDB: MySQL 8.0\nFlag: {FLAG_WEB}\nEnv: {dict(os.environ)}</pre>")),
            "/console": lambda: self._send(page("Console", "<p>Debug console (simulated)</p><p>Try: ?cmd=id</p>")),
            "/phpinfo.php": lambda: self._send(page("phpinfo()", f"<table><tr><td>System</td><td>Linux ctflab 5.4.0</td></tr><tr><td>PHP Version</td><td>7.4.3</td></tr><tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr><tr><td>DB_PASSWORD</td><td>SuperSecret123!</td></tr></table>")),
            "/backup.zip": lambda: self._send(b"PK\x03\x04" + b"\x00"*20 + b"flag.txt" + FLAG_WEB.encode(), ct="application/zip"),
            "/wp-login.php": lambda: self._send(page("WordPress Login", '<form method=post><input name=log placeholder=username><input name=pwd type=password><input type=submit></form>')),
        }

        # 动态路由: /api/user/1, /api/user/2, ...
        if path.startswith("/api/user/"):
            uid = path.split("/")[-1]
            self._api_user_by_id(uid)
            return
        if path.startswith("/download"):
            self._download(q)
            return
        if path.startswith("/redirect"):
            self._redirect(q)
            return

        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._send(page("404", "<p>Not Found</p>"), 404)

    def do_POST(self):
        p = urlparse(self.path)
        body = self._get_body()
        routes = {
            "/login": lambda: self._login_post(body),
            "/search": lambda: self._search_post(body),
            "/ping": lambda: self._ping_post(body),
            "/render": lambda: self._render_post(body),
            "/notes": lambda: self._notes_post(body),
            "/upload": lambda: self._upload_post(body),
            "/api/login": lambda: self._api_login(body),
            "/graphql": lambda: self._handle_graphql_post(body),
        }
        handler = routes.get(p.path)
        if handler:
            handler()
        else:
            self._send(page("404","<p>Not Found</p>"), 404)

    # ── 页面 ──────────────────────────────────────────────
    def _home(self):
        self._send(page("CTF Range v2", '''
        <h2>Available Vulnerabilities</h2>
        <div class=vuln><b>1. SQL Injection</b> — <a href="/search">/search</a> (POST: q)</div>
        <div class=vuln><b>2. Command Injection</b> — <a href="/ping">/ping</a> (POST: host)</div>
        <div class=vuln><b>3. LFI</b> — <a href="/tools?page=index">/tools?page=</a></div>
        <div class=vuln><b>4. SSTI</b> — <a href="/render">/render</a> (POST: template)</div>
        <div class=vuln><b>5. XSS</b> — <a href="/notes">/notes</a> (POST: note)</div>
        <div class=vuln><b>6. IDOR</b> — <a href="/api/user/1">/api/user/{id}</a></div>
        <div class=vuln><b>7. File Upload</b> — <a href="/upload">/upload</a></div>
        <div class=vuln><b>8. SSRF</b> — <a href="/redirect?url=http://internal">/redirect?url=</a></div>
        <div class=vuln><b>9. GraphQL</b> — <a href="/graphql">/graphql</a></div>
        <div class=vuln><b>10. API未授权</b> — <a href="/api/secrets">/api/secrets</a></div>
        <div class=vuln><b>11. .git泄露</b> — <a href="/.git/HEAD">/.git/HEAD</a></div>
        <div class=vuln><b>12. .env泄露</b> — <a href="/.env">/.env</a></div>
        <div class=vuln><b>13. actuator</b> — <a href="/actuator/env">/actuator/env</a></div>
        <div class=vuln><b>14. Debug</b> — <a href="/debug">/debug</a></div>
        <p style="color:#888">14 vulnerability types · Real CTF practice</p>
        '''))

    def _login_page(self):
        self._send(page("Login", '<form method=post><input name=user placeholder=Username><input name=pass type=password placeholder=Password><input type=submit value=Login></form><p>Hint: admin/admin123</p>'))

    def _login_post(self, body):
        params = parse_qs(body)
        user = params.get("user",[""])[0]
        pwd = params.get("pass",[""])[0]
        conn = sqlite3.connect(DB)
        # SQLi漏洞: 直接拼接
        try:
            cur = conn.execute(f"SELECT id,username,role FROM users WHERE username='{user}' AND password='{pwd}'")
            row = cur.fetchone()
            if row:
                self._send(page("Login Success", f"<p>Welcome {row[1]}! Role: {row[2]}</p><p>Token: {row[0]}_{row[1]}_token</p><p>Flag: {FLAG_AUTH}</p>"))
            else:
                self._send(page("Login Failed", "<p>Invalid credentials</p><p><a href=/login>Try again</a></p>"))
        except Exception as e:
            self._send(page("Error", f"<pre>SQL Error: {e}</pre>"))
        conn.close()

    def _search(self):
        self._send(page("Search", '<form method=post><input name=q placeholder="Search products..."><input type=submit></form><p>Try: flag, admin, secret</p>'))

    def _search_post(self, body):
        params = parse_qs(body)
        q = params.get("q",[""])[0]
        conn = sqlite3.connect(DB)
        try:
            # SQLi漏洞
            cur = conn.execute(f"SELECT id,name,price,description FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'")
            rows = cur.fetchall()
            if rows:
                table = "<table><tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th></tr>"
                for r in rows:
                    table += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td></tr>"
                table += "</table>"
                self._send(page("Search Results", table + '<form method=post><input name=q><input type=submit></form>'))
            else:
                self._send(page("No Results", f"<p>No results for: {q}</p>" + '<form method=post><input name=q><input type=submit></form>'))
        except Exception as e:
            self._send(page("Error", f"<pre>SQL Error: {e}</pre>"))
        conn.close()

    def _ping_page(self):
        self._send(page("Network Ping", '<form method=post><input name=host value="127.0.0.1" placeholder="IP or hostname"><input type=submit value="Ping"></form>'))

    def _ping_post(self, body):
        params = parse_qs(body)
        host = params.get("host",[""])[0]
        try:
            out = subprocess.check_output(f"ping -c 2 {host}", shell=True, stderr=subprocess.STDOUT, timeout=10)
            self._send(page("Ping Result", f"<pre>{out.decode()}</pre>" + '<form method=post><input name=host><input type=submit></form>'))
        except subprocess.CalledProcessError as e:
            self._send(page("Ping Error", f"<pre>{e.output.decode()}</pre>"))
        except subprocess.TimeoutExpired:
            self._send(page("Ping Timeout", "<p>Command timed out</p>"))

    def _render_page(self):
        self._send(page("Template Renderer", '<form method=post><p>Template:</p><textarea name=template rows=5 cols=60>Hello {{name}}!</textarea><br><input type=submit value=Render></form><p>Try: {{7*7}}, {{config}}, {{self.__class__}}</p>'))

    def _render_post(self, body):
        params = parse_qs(body)
        tpl = params.get("template",[""])[0]
        try:
            if "{{" in tpl:
                expr = tpl.replace("{{","").replace("}}","")
                result = str(eval(expr))
            else:
                result = tpl.replace("{name}","Guest")
            self._send(page("Rendered", f"<pre>{result}</pre>"))
        except Exception as e:
            self._send(page("Render Error", f"<pre>Error: {e}</pre>"))

    def _notes(self):
        self._send(page("Notes", '''
        <form method=post><textarea name=note rows=3 cols=60 placeholder="Write a note..."></textarea><br><input type=submit value="Post Note"></form>
        <h2>Recent Notes</h2>
        <div class=vuln>admin: Remember to change the default password!</div>
        <div class=vuln>user1: The flag is somewhere on this server...</div>
        '''))

    def _notes_post(self, body):
        params = parse_qs(body)
        note = params.get("note",[""])[0]
        # XSS漏洞: 直接输出
        self._send(page("Notes", f'''
        <form method=post><textarea name=note rows=3 cols=60></textarea><br><input type=submit></form>
        <h2>Recent Notes</h2>
        <div class=vuln>admin: Remember to change the default password!</div>
        <div class=vuln>user1: The flag is somewhere on this server...</div>
        <div class=vuln>guest: {note}</div>
        '''))

    def _tools(self):
        q = self._get_params()
        page_name = q.get("page",["index"])[0]
        if page_name == "index":
            self._send(page("Tools", "<p>Welcome to the tools page.</p><p>Try: ?page=about, ?page=config</p>"))
        else:
            try:
                with open(page_name) as f:
                    content = f.read()
                self._send(page(f"Tools: {page_name}", f"<pre>{content}</pre>"))
            except Exception as e:
                self._send(page("Error", f"<pre>{e}</pre>"))

    def _crypto(self):
        self._send(page("Crypto Challenge", f'''
        <h2>Decode the message</h2>
        <pre>{base64.b64encode(FLAG_CRYPTO.encode()).decode()}</pre>
        <p>Encoding: Base64</p>
        <h2>Hash challenge</h2>
        <pre>{hashlib.md5(b"admin123").hexdigest()}</pre>
        <p>Find the plaintext of this MD5 hash</p>
        <h2>XOR challenge</h2>
        <pre>{FLAG_WEB.encode().hex()}</pre>
        <p>XOR key: 0x42</p>
        '''))

    def _upload_page(self):
        self._send(page("File Upload", '<form method=post enctype=multipart/form-data><input type=file name=file><br><input type=submit value=Upload></form><p>Allowed: jpg, png, gif, txt</p>'))

    def _upload_post(self, body):
        self._send(page("Upload Result", "<p>File uploaded successfully!</p><p>Check /uploads/ for your file</p>"))

    def _admin(self):
        self._send(page("Admin Panel", f'''
        <h2>Admin Dashboard</h2>
        <p>Welcome, Admin!</p>
        <table>
        <tr><td>Users</td><td>4</td></tr>
        <tr><td>Orders</td><td>2</td></tr>
        <tr><td>Secret Flag</td><td>{FLAG_AUTH}</td></tr>
        </table>
        <h3>Quick Links</h3>
        <a href="/api/users">User Management</a><br>
        <a href="/api/secrets">Secret Management</a><br>
        <a href="/api/config">System Config</a>
        '''))

    def _api_users(self):
        conn = sqlite3.connect(DB)
        rows = conn.execute("SELECT id,username,role,email,token FROM users").fetchall()
        conn.close()
        data = [{"id":r[0],"username":r[1],"role":r[2],"email":r[3],"token":r[4]} for r in rows]
        self._send(json.dumps(data, indent=2), ct="application/json")

    def _api_user(self):
        self._send(json.dumps({"error":"missing id parameter"}), 400, "application/json")

    def _api_user_by_id(self, uid):
        conn = sqlite3.connect(DB)
        row = conn.execute(f"SELECT id,username,role,email,token FROM users WHERE id={uid}").fetchone()
        conn.close()
        if row:
            self._send(json.dumps({"id":row[0],"username":row[1],"role":row[2],"email":row[3],"token":row[4]}), ct="application/json")
        else:
            self._send(json.dumps({"error":"not found"}), 404, "application/json")

    def _api_secrets(self):
        conn = sqlite3.connect(DB)
        rows = conn.execute("SELECT id,user_id,key,value FROM secrets").fetchall()
        conn.close()
        data = [{"id":r[0],"user_id":r[1],"key":r[2],"value":r[3]} for r in rows]
        self._send(json.dumps(data, indent=2), ct="application/json")

    def _api_orders(self):
        conn = sqlite3.connect(DB)
        rows = conn.execute("SELECT id,user_id,product,amount FROM orders").fetchall()
        conn.close()
        data = [{"id":r[0],"user_id":r[1],"product":r[2],"amount":r[3]} for r in rows]
        self._send(json.dumps(data, indent=2), ct="application/json")

    def _api_config(self):
        self._send(json.dumps({
            "db":{"host":"localhost","user":"root","password":"SuperSecret123!"},
            "redis":{"host":"127.0.0.1","port":6379},
            "secret_key":"myflasksecret",
            "flag":FLAG_WEB
        }, indent=2), ct="application/json")

    def _api_health(self):
        self._send(json.dumps({"status":"ok","version":"1.0","uptime":int(time.time())}), ct="application/json")

    def _api_login(self, body):
        params = parse_qs(body)
        user = params.get("user",[""])[0]
        pwd = params.get("pass",[""])[0]
        conn = sqlite3.connect(DB)
        try:
            row = conn.execute(f"SELECT id,username,role,token FROM users WHERE username='{user}' AND password='{pwd}'").fetchone()
            if row:
                self._send(json.dumps({"status":"ok","user":row[1],"role":row[2],"token":row[3]}), ct="application/json")
            else:
                self._send(json.dumps({"status":"fail","message":"invalid credentials"}), 401, "application/json")
        except Exception as e:
            self._send(json.dumps({"error":str(e)}), 500, "application/json")
        conn.close()

    def _redirect(self):
        q = self._get_params()
        url = q.get("url",["/"])[0]
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def _download(self):
        q = self._get_params()
        f = q.get("file",[""])[0]
        try:
            with open(f) as fh:
                self._send(fh.read(), ct="text/plain")
        except:
            self._send("File not found", 404)

    def _handle_graphql(self, q):
        query = q.get("query",["{ __schema { types { name } } }"])[0]
        if "__schema" in query:
            data = {"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"},{"name":"Secret"},{"name":"Flag"}]}}}
        elif "users" in query.lower():
            conn = sqlite3.connect(DB)
            rows = conn.execute("SELECT id,username,role FROM users").fetchall()
            conn.close()
            data = {"data":{"users":[{"id":r[0],"username":r[1],"role":r[2]} for r in rows]}}
        elif "flag" in query.lower():
            data = {"data":{"flag":FLAG_WEB}}
        else:
            data = {"data":{"hello":"world"}}
        self._send(json.dumps(data), ct="application/json")

    def _handle_graphql_post(self, body):
        try:
            req = json.loads(body)
            query = req.get("query","")
        except:
            query = body
        if "flag" in query.lower():
            data = {"data":{"flag":FLAG_WEB}}
        elif "users" in query.lower():
            conn = sqlite3.connect(DB)
            rows = conn.execute("SELECT id,username,role FROM users").fetchall()
            conn.close()
            data = {"data":{"users":[{"id":r[0],"username":r[1],"role":r[2]} for r in rows]}}
        else:
            data = {"data":{"hello":"world"}}
        self._send(json.dumps(data), ct="application/json")

if __name__ == "__main__":
    print("CTF Range v2 started on http://0.0.0.0:7777")
    print(f"Flags: {FLAG_WEB}")
    HTTPServer(("0.0.0.0", 7777), H).serve_forever()
