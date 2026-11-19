#!/usr/bin/env python3
"""Restore Antigravity credentials through the local macOS Keychain."""
import argparse
import base64
import datetime as dt
import hashlib
import http.server
import json
from pathlib import Path
import re
import secrets
import struct
import subprocess
import threading
import time
import shutil
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
KEYCHAIN = HERE / '.build' / 'external-keychain'
BINARY = Path('/Applications/Antigravity.app/Contents/Resources/bin/language_server')

class NativeImage:
    """Read only the installed ARM64 Mach-O metadata needed for OAuth configuration."""

    def __init__(self, path):
        self.path = path
        try:
            self.data = path.read_bytes()
        except OSError:
            raise RuntimeError('无法读取已安装的 Antigravity language_server') from None
        if len(self.data) < 32 or struct.unpack_from('<II', self.data) != (0xfeedfacf, 0x0100000c):
            raise RuntimeError('当前脚本只适配 macOS Apple Silicon 的原生程序结构')
        self.segments = []
        self.sections = {}
        position = 32
        for _ in range(struct.unpack_from('<I', self.data, 16)[0]):
            command, length = struct.unpack_from('<II', self.data, position)
            if length < 8 or position + length > len(self.data):
                raise RuntimeError('原生程序结构已变化，脚本暂不兼容')
            if command == 0x19:
                address, _, offset, size = struct.unpack_from('<QQQQ', self.data, position + 24)
                if size:
                    self.segments.append((address, address + size, offset))
                for j in range(struct.unpack_from('<I', self.data, position + 64)[0]):
                    at = position + 72 + j * 80
                    name, _, address, size, offset = struct.unpack_from('<16s16sQQI', self.data, at)
                    self.sections[name.rstrip(b'\0').decode()] = (address, size, offset)
            position += length

    def raw(self, address, length):
        for start, end, offset in self.segments:
            if start <= address and address + length <= end:
                at = offset + address - start
                return self.data[at:at + length]
        raise ValueError('Unmapped native data')

    def unpack(self, fmt, address):
        return struct.unpack(fmt, self.raw(address, struct.calcsize(fmt)))

    def string(self, address):
        pointer, length = self.unpack('<QQ', address)
        if length > 10000:
            raise ValueError('Unexpected native string length')
        return self.raw(pointer, length).decode() if length else ''

    def function_code(self, suffix):
        try:
            header = self.sections['__lrodata_gopcln'][2]
            text = self.sections['__text'][0]
        except KeyError:
            raise RuntimeError('原生函数表已变化，脚本暂不兼容') from None
        count, _, _, names_offset, _, _, _, functions_offset = struct.unpack_from('<8Q', self.data, header + 8)
        if not 0 < count < 1_000_000:
            raise RuntimeError('原生函数表不符合预期，脚本暂不兼容')
        table, names = header + functions_offset, header + names_offset
        matches = []
        for index in range(count - 1):
            pc, metadata = struct.unpack_from('<II', self.data, table + index * 8)
            name_offset = struct.unpack_from('<i', self.data, table + metadata + 4)[0]
            start = names + name_offset
            end = self.data.find(b'\0', start)
            if end < start:
                raise RuntimeError('原生函数名不符合预期，脚本暂不兼容')
            if self.data[start:end].decode(errors='replace').endswith(suffix):
                next_pc = struct.unpack_from('<I', self.data, table + (index + 1) * 8)[0]
                matches.append((text + pc, text + next_pc))
        if len(matches) != 1:
            raise RuntimeError('无法唯一识别原生 OAuth 配置，脚本暂不兼容')
        start, end = matches[0]
        try:
            return subprocess.check_output([
                'xcrun', 'llvm-objdump', '-d', '--no-show-raw-insn',
                f'--start-address={start}', f'--stop-address={end}', str(self.path)
            ], text=True, stderr=subprocess.PIPE, timeout=20)
        except (OSError, subprocess.SubprocessError):
            raise RuntimeError('无法解析原生 OAuth 配置，请检查 Xcode Command Line Tools 或版本兼容性') from None

def installed_oauth_config():
    native = NativeImage(BINARY)
    assembly = native.function_code('codeassistclient.getOAuth2Config')
    constants = []
    pattern = re.compile(
        r'adrp\s+(x\d+), (0x[0-9a-f]+)[^\n]*\n[^\n]*add\s+\1, \1, #(0x[0-9a-f]+)\s*\n'
        r'[^\n]*mov\s+x\d+, #(0x[0-9a-f]+)')
    for m in pattern.finditer(assembly):
        addr = int(m[2], 16) + int(m[3], 16)
        length = int(m[4], 16)
        if 0 < length < 1000:
            try: constants.append(native.raw(addr, length).decode())
            except (ValueError, UnicodeError): pass
    ids = [v for v in constants if re.fullmatch(r'[a-zA-Z0-9_-]+\.apps\.googleusercontent\.com', v)]
    private_config = [v for v in constants if v.startswith('GOCSPX-')]
    if len(ids) != 1 or len(private_config) != 1:
        raise RuntimeError('Installed OAuth configuration format has changed')
    # Discover the scope slice through the same compiled function, not a version/address table.
    scopes = []
    for m in re.finditer(r'adrp\s+x27, (0x[0-9a-f]+)[^\n]*\n[^\n]*add\s+x27, x27, #(0x[0-9a-f]+)\s*\n[^\n]*ldp\s+x\d+, x\d+, \[x27\]', assembly):
        try:
            start, count, capacity = native.unpack('<QQQ', int(m[1],16)+int(m[2],16))
            if not 1 <= count <= capacity <= 20: continue
            values = [native.string(start+i*16) for i in range(count)]
            if all(v.startswith('https://www.googleapis.com/auth/') for v in values): scopes = values
        except (ValueError, UnicodeError, struct.error): pass
    # The personal login path adds the installed aicode scope.
    for v in constants:
        if v.startswith('https://www.googleapis.com/auth/') and v not in scopes: scopes.append(v)
    if not scopes or 'https://www.googleapis.com/auth/aicode' not in scopes:
        raise RuntimeError('Could not verify the installed personal login scopes')
    return dict(client_id=ids[0], client_secret=private_config[0], scopes=scopes)

def ensure_keychain_helper():
    source = HERE / 'external-keychain.swift'
    if KEYCHAIN.exists() and KEYCHAIN.stat().st_mtime >= source.stat().st_mtime:
        return
    compiler = shutil.which('swiftc')
    if not compiler: raise RuntimeError('需要安装 Xcode Command Line Tools，以构建本机钥匙串 helper')
    KEYCHAIN.parent.mkdir(mode=0o700,exist_ok=True)
    result = subprocess.run([compiler,'-module-cache-path',str(KEYCHAIN.parent/'swift-module-cache'),str(source),'-o',str(KEYCHAIN)],capture_output=True)
    if result.returncode: raise RuntimeError('无法构建钥匙串 helper，请检查 Xcode Command Line Tools')

def keychain(action, account='oauth', value=None):
    ensure_keychain_helper()
    request = dict(action=action, account=account)
    if value is not None: request['value'] = value
    result = subprocess.run([str(KEYCHAIN)], input=json.dumps(request).encode(), capture_output=True)
    if result.returncode:
        match = re.search(rb'failed \((-?\d+)\)',result.stderr)
        code = match[1].decode() if match else 'unknown'
        raise RuntimeError(f'Could not access the external login Keychain item ({code})')
    return result.stdout

def post_token(config, parameters):
    body = urllib.parse.urlencode(dict(parameters, client_id=config['client_id'], client_secret=config['client_secret'])).encode()
    request = urllib.request.Request('https://oauth2.googleapis.com/token', data=body, headers={'Content-Type':'application/x-www-form-urlencoded'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response: result = json.load(response)
    except urllib.error.HTTPError as error:
        # OAuth error codes are safe; never log the response body or request.
        try: code = json.loads(error.read()).get('error', 'unknown')
        except Exception: code = 'unknown'
        raise RuntimeError(f'Google token exchange rejected: {error.code} ({code})') from None
    if not result.get('access_token'): raise RuntimeError('Google returned no access token')
    return result

def native_token(response):
    token = {k:response[k] for k in ['access_token','refresh_token','token_type','id_token'] if response.get(k)}
    token['expiry'] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=int(response.get('expires_in',3600)))).isoformat().replace('+00:00','Z')
    return {'token': token}

def login(config, open_browser=True):
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    done = threading.Event()
    outcome = {}
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def redirect(self, target):
            self.send_response(302); self.send_header('Location',target); self.send_header('Cache-Control','no-store'); self.end_headers()
        def do_GET(self):
            if self.headers.get('Host') != f'127.0.0.1:{self.server.server_port}':
                self.send_error(403); return
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path == '/start': self.redirect(auth_url); return
            if parsed.path == '/callback':
                params = urllib.parse.parse_qs(parsed.query)
                if not secrets.compare_digest(params.get('state',[''])[0], state): self.send_error(403); return
                if outcome: self.send_error(409); return
                try:
                    if params.get('error'): raise RuntimeError('Google login was cancelled or denied')
                    code = params.get('code',[''])[0]
                    if not code: raise RuntimeError('Google returned no authorization code')
                    response = post_token(config,dict(grant_type='authorization_code',code=code,redirect_uri=redirect_uri,code_verifier=verifier))
                    if not response.get('refresh_token'): raise RuntimeError('Google returned no refresh token; no credentials were saved')
                    refreshed = post_token(config,dict(grant_type='refresh_token',refresh_token=response['refresh_token']))
                    refreshed['refresh_token'] = refreshed.get('refresh_token',response['refresh_token'])
                    if response.get('id_token'): refreshed['id_token'] = response['id_token']
                    stored = native_token(refreshed)
                    keychain('save', value=json.dumps(stored))
                    outcome['saved'] = True
                    print(json.dumps(dict(loginSucceeded=True, refreshVerified=True, savedToKeychain=True)),flush=True)
                except Exception as error:
                    outcome['error'] = str(error)
                    print(json.dumps(dict(loginSucceeded=False,error=str(error))),flush=True)
                self.redirect('/done'); done.set(); return
            if parsed.path == '/done':
                body = ('<meta charset="utf-8"><title>Antigravity external login</title><h2>' + ('登录凭据已安全保存，可以关闭此页。' if outcome.get('saved') else '登录未完成，请查看本地脚本。') + '</h2>').encode()
                self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body); return
            self.send_error(404)
    server = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    redirect_uri = f'http://127.0.0.1:{server.server_port}/callback'
    params = dict(client_id=config['client_id'],redirect_uri=redirect_uri,response_type='code',scope=' '.join(config['scopes']),state=state,code_challenge=challenge,code_challenge_method='S256',access_type='offline',prompt='consent')
    auth_url = 'https://accounts.google.com/o/oauth2/auth?' + urllib.parse.urlencode(params)
    thread = threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    print(json.dumps(dict(openLoginUrl=f'http://127.0.0.1:{server.server_port}/start',scopeCount=len(config['scopes']))),flush=True)
    if open_browser:
        subprocess.run(['open',f'http://127.0.0.1:{server.server_port}/start'],check=True,capture_output=True)
    done.wait(300)
    # Keep /done available briefly for the redirect; never log its callback URL.
    if done.is_set(): threading.Event().wait(2)
    server.shutdown();server.server_close()
    if not outcome.get('saved'): raise RuntimeError(outcome.get('error','Google login timed out'))

def export_native(config):
    stored = json.loads(keychain('load'))
    token = stored.get('token',{})
    if not token.get('refresh_token'): raise RuntimeError('No refresh token in external Keychain item')
    response = post_token(config,dict(grant_type='refresh_token',refresh_token=token['refresh_token']))
    response['refresh_token'] = response.get('refresh_token',token['refresh_token'])
    stored['token'] = native_token(response)['token']
    keychain('save',value=json.dumps(stored))
    existing = subprocess.run(['/usr/bin/security','find-generic-password','-s','gemini','-a','antigravity','-w'],capture_output=True)
    if existing.returncode == 0:
        backup = 'native-keyring-backup-'+dt.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3)
        keychain('save',account=backup,value=existing.stdout.decode().rstrip('\n'))
    elif existing.returncode != 44:
        raise RuntimeError('Could not back up the original native Keychain item')
    envelope = 'go-keyring-base64:' + base64.b64encode(json.dumps(stored).encode()).decode()
    keychain('provide-native',account='antigravity',value=envelope)
    print(json.dumps(dict(nativeKeychainCredentialWritten=True,hasRefreshToken=True)),flush=True)

def start(config):
    # Never quit an app that may be running the user's agents or editing a draft.
    running = subprocess.run(['/usr/bin/pgrep','-x','Antigravity'],capture_output=True)
    if running.returncode == 0: raise RuntimeError('Antigravity 已在运行。请先正常退出，再运行 start；脚本不会强行结束任务。')
    if running.returncode != 1: raise RuntimeError('无法检查 Antigravity 是否运行，已停止启动')
    node = shutil.which('node')
    frontend = HERE / 'antigravity-skip-region-page.mjs'
    if not node or not frontend.exists(): raise RuntimeError('需要 Node.js 22+ 和同目录的页面跳过脚本')
    version = subprocess.run([node,'-p','process.versions.node.split(".")[0]'],capture_output=True,text=True)
    if version.returncode or not version.stdout.strip().isdigit() or int(version.stdout.strip()) < 22:
        raise RuntimeError('需要 Node.js 22 或更新版本')
    export_native(config)
    subprocess.run(['open','-a','/Applications/Antigravity.app','--args','--remote-debugging-port=0'],check=True,capture_output=True)
    for attempt in range(25):
        check = subprocess.run([node,str(frontend),'--check'],capture_output=True,text=True,timeout=30)
        if check.returncode == 0:
            if '当前账号资格检查显示地区限制' in check.stdout:
                subprocess.run([node,str(frontend)],check=True,timeout=60)
            else: print('原版应用已恢复登录。')
            return
        if '不兼容' in check.stderr or '匹配' in check.stderr:
            raise RuntimeError(check.stderr.strip())
        time.sleep(1)
    raise RuntimeError('启动后未能确认登录状态。请运行同目录页面脚本的 --check 检查；可能已不兼容当前版本。')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command',choices=['check','login','provide','start'])
    parser.add_argument('--no-browser',action='store_true',help='登录时只显示本机登录链接')
    args = parser.parse_args()
    config = installed_oauth_config()
    if args.command == 'check':
        check = subprocess.run(['/usr/bin/security','find-generic-password','-s','Antigravity External Login','-a','oauth'],capture_output=True)
        print(json.dumps(dict(installedConfigRecognized=True,scopeCount=len(config['scopes']),keychainHelperBuilt=KEYCHAIN.exists(),externalCredentialExists=check.returncode==0)))
    elif args.command == 'login': login(config,open_browser=not args.no_browser)
    elif args.command == 'start': start(config)
    else: export_native(config)

if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps(dict(error=str(error)),ensure_ascii=False),flush=True); raise SystemExit(1)
