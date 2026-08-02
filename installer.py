#!/usr/bin/env python3
"""
TextCord installer — replaces the old install.sh.

Designed to be run as root on Linux (Debian/Ubuntu/Fedora/openSUSE/Arch)
either directly:    sudo python3 installer.py
or compiled to a single binary via PyInstaller (see build_binary.sh).

Flow:
  1. Ask for domain TLD  (textcord.<tld>)
  2. Ask for listening interface(s)
  3. Ask whether to enable HSTS
  4. Ask for certificate name (created in ~/certs/ if missing)
  5. Configure nginx (HTTPS reverse proxy -> 127.0.0.1:5000) + autostart
  6. Print one-time admin setup URL: https://textcord.<tld>/o/admin/<80-char-token>
  7. App keeps running under autostart; installer exits.
"""
import os, sys, subprocess, secrets, shutil, getpass, socket, textwrap, pathlib, time

APP_DIR     = os.path.dirname(os.path.abspath(__file__))
INSTALL_DIR = '/opt/textcord'
DATA_DIR    = '/var/lib/textcord'
CONF_FILE   = '/etc/textcord.conf'
TOKEN_FILE  = '/var/lib/textcord/setup_token'
SERVICE     = '/etc/systemd/system/textcord.service'
NGINX_SITE  = '/etc/nginx/sites-available/textcord'
NGINX_LINK  = '/etc/nginx/sites-enabled/textcord'
NGINX_CONFD = '/etc/nginx/conf.d/textcord.conf'  # fallback for distros without sites-enabled

def is_frozen():
    return bool(getattr(sys, 'frozen', False))

def bundle_dir():
    return getattr(sys, '_MEIPASS', APP_DIR)

def resource_path(name):
    return os.path.join(bundle_dir() if is_frozen() else APP_DIR, name)

BANNER = r"""
   ████████╗███████╗██╗  ██╗████████╗ ██████╗ ██████╗ ██████╗ ██████╗
   ╚══██╔══╝██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔══██╗
      ██║   █████╗   ╚███╔╝    ██║   ██║     ██║   ██║██████╔╝██║  ██║
      ██║   ██╔══╝   ██╔██╗    ██║   ██║     ██║   ██║██╔══██╗██║  ██║
      ██║   ███████╗██╔╝ ██╗   ██║   ╚██████╗╚██████╔╝██║  ██║██████╔╝
      ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝
                       Installer · binary distribution
"""

def must_root():
    if os.geteuid() != 0:
        print("This installer must be run as root (sudo)."); sys.exit(1)

def run(cmd, check=True, **kw):
    print(f"  $ {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check, **kw)

def ask(prompt, default=None, choices=None):
    while True:
        suffix = f" [{default}]" if default else ""
        if choices: suffix = f" ({'/'.join(choices)})" + suffix
        val = input(f"  {prompt}{suffix}: ").strip()
        if not val and default is not None: val = default
        if choices and val.lower() not in [c.lower() for c in choices]:
            print(f"   ! choose one of: {', '.join(choices)}"); continue
        if val: return val

def list_interfaces():
    try:
        out = subprocess.check_output(['ip', '-o', '-4', 'addr', 'show'], text=True)
        ifs = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ifs.append((parts[1], parts[3].split('/')[0]))
        return ifs
    except Exception:
        return [('lo', '127.0.0.1')]

def detect_distro():
    try:
        d = {}
        for line in open('/etc/os-release'):
            k, _, v = line.strip().partition('=')
            d[k] = v.strip('"')
        return d.get('ID', 'linux').lower()
    except Exception: return 'linux'

def pkg_install(packages):
    distro = detect_distro()
    if distro in ('debian', 'ubuntu', 'raspbian', 'linuxmint', 'pop'):
        run(['apt-get', 'update'])
        run(['apt-get', 'install', '-y'] + packages)
    elif distro in ('fedora', 'rhel', 'centos', 'rocky', 'almalinux'):
        run(['dnf', 'install', '-y'] + packages)
    elif distro in ('opensuse-leap', 'opensuse-tumbleweed', 'sles', 'opensuse'):
        run(['zypper', '-n', 'install'] + packages)
    elif distro in ('arch', 'manjaro', 'endeavouros'):
        run(['pacman', '-Sy', '--noconfirm'] + packages)
    else:
        print(f"  ! Unknown distro '{distro}'. Please install manually: {' '.join(packages)}")

def system_python():
    return shutil.which('python3') or '/usr/bin/python3'

def install_app_files():
    """Copy bundled/source application files to a stable path.
    This avoids systemd failures when the installer is launched from a path
    containing spaces and prevents PyInstaller from re-running the installer
    as if it were the application.
    """
    # Purge any leftovers from a previous install so stale DB / templates /
    # setup tokens can never leak into a fresh setup.
    try:
        subprocess.run(['systemctl', 'stop', 'textcord.service'],
                       check=False, capture_output=True)
    except Exception:
        pass
    for path in (INSTALL_DIR, DATA_DIR):
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    try: os.remove(TOKEN_FILE)
    except Exception: pass
    os.makedirs(INSTALL_DIR, exist_ok=True)
    for filename in ('app.py', 'models.py', 'requirements.txt'):
        src = resource_path(filename)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(INSTALL_DIR, filename))
    for dirname in ('templates', 'static'):
        src = resource_path(dirname)
        dst = os.path.join(INSTALL_DIR, dirname)
        if os.path.isdir(src):
            shutil.copytree(src, dst, dirs_exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

def ensure_app_venv():
    venv = os.path.join(INSTALL_DIR, 'venv')
    py = os.path.join(venv, 'bin', 'python')
    if not os.path.exists(py):
        result = run([system_python(), '-m', 'venv', venv], check=False)
        if result.returncode != 0:
            distro = detect_distro()
            if distro in ('debian', 'ubuntu', 'raspbian', 'linuxmint', 'pop'):
                pkg_install(['python3-venv'])
            result = run([system_python(), '-m', 'venv', venv], check=False)
            if result.returncode != 0:
                raise RuntimeError('Could not create /opt/textcord/venv. Install python3-venv and retry.')
    run([py, '-m', 'pip', 'install', '--upgrade', 'pip'], check=False)
    req = os.path.join(INSTALL_DIR, 'requirements.txt')
    if os.path.isfile(req):
        run([py, '-m', 'pip', 'install', '-r', req])
    return py

def ensure_deps():
    needed = ['nginx', 'openssl', 'python3']
    missing = [p for p in needed if not shutil.which(p)]
    if missing:
        print(f"  Installing system deps: {missing}")
        pkg_install(needed)
    ensure_app_venv()

def gen_cert(cert_name, domain, certs_dir):
    os.makedirs(certs_dir, exist_ok=True)
    crt = os.path.join(certs_dir, f'{cert_name}.crt')
    key = os.path.join(certs_dir, f'{cert_name}.key')
    if os.path.isfile(crt) and os.path.isfile(key):
        print(f"  Reusing existing cert: {crt}")
        return crt, key
    subj = f"/C=US/ST=Local/L=Local/O=TextCord/CN={domain}"
    run(['openssl', 'req', '-x509', '-nodes', '-days', '3650',
         '-newkey', 'rsa:2048', '-keyout', key, '-out', crt, '-subj', subj])
    return crt, key

def write_nginx(domain, crt, key, hsts, listen_ip):
    listen_directive = f"listen {listen_ip}:443 ssl;" if listen_ip not in ('0.0.0.0', '*') else "listen 443 ssl;"
    hsts_h = 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;' if hsts else ''
    conf = f"""
# Plain HTTP is never served — always redirect to HTTPS.
server {{
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://{domain}$request_uri;
}}

server {{
    {listen_directive}
    server_name {domain};

    if ($host != "{domain}") {{ return 444; }}

    ssl_certificate     {crt};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    {hsts_h}

    client_max_body_size 32M;

    location / {{
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }}
}}
""".strip() + "\n"
    target = NGINX_SITE if os.path.isdir('/etc/nginx/sites-available') else NGINX_CONFD
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, 'w') as f: f.write(conf)
    if target == NGINX_SITE:
        if os.path.exists(NGINX_LINK): os.remove(NGINX_LINK)
        os.symlink(NGINX_SITE, NGINX_LINK)
        default_link = '/etc/nginx/sites-enabled/default'
        if os.path.exists(default_link):
            try: os.remove(default_link)
            except Exception: pass
    run(['nginx', '-t'])
    run(['systemctl', 'enable', '--now', 'nginx'], check=False)
    run(['systemctl', 'reload', 'nginx'], check=False)

def write_service():
    app_python = os.path.join(INSTALL_DIR, 'venv', 'bin', 'python')
    unit = f"""[Unit]
Description=TextCord application
After=network.target

[Service]
Type=simple
WorkingDirectory={INSTALL_DIR}
EnvironmentFile=-{CONF_FILE}
Environment=TEXTCORD_HOST=127.0.0.1
Environment=TEXTCORD_PORT=5000
Environment=PYTHONUNBUFFERED=1
ExecStart={app_python} {INSTALL_DIR}/app.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
"""
    with open(SERVICE, 'w') as f: f.write(unit)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', 'textcord.service'], check=False)
    run(['systemctl', 'restart', 'textcord.service'])

def wait_for_app():
    for _ in range(15):
        try:
            with socket.create_connection(('127.0.0.1', 5000), timeout=1):
                return True
        except OSError:
            time.sleep(1)
    run(['systemctl', 'status', 'textcord.service', '--no-pager', '-l'], check=False)
    try:
        run(['journalctl', '-u', 'textcord.service', '-n', '80', '--no-pager'], check=False)
    except Exception:
        pass
    raise RuntimeError('TextCord did not start on 127.0.0.1:5000; see logs above.')

def write_token(token):
    os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
    with open(TOKEN_FILE, 'w') as f: f.write(token)
    os.chmod(TOKEN_FILE, 0o600)

def write_conf(domain, hsts, allow_reg='no'):
    with open(CONF_FILE, 'w') as f:
        f.write(f"DOMAIN={domain}\nHSTS={'yes' if hsts else 'no'}\nALLOW_REGISTRATION={allow_reg}\n")
    os.chmod(CONF_FILE, 0o644)

def ensure_hosts(domain):
    """Add <server_ip> <domain> to /etc/hosts (so the server itself resolves
    the domain to a routable LAN IP, not just 127.0.0.1)."""
    ip = _primary_lan_ip()
    try:
        try: content = open('/etc/hosts').read()
        except Exception: content = ''
        # Strip any previous entry for this domain to avoid stale 127.0.0.1
        new_lines = [l for l in content.splitlines() if domain not in l.split()]
        new_lines.append(f"{ip} {domain}")
        with open('/etc/hosts', 'w') as f:
            f.write('\n'.join(new_lines) + '\n')
    except Exception as e:
        print(f"  ! Could not update /etc/hosts: {e}")

def _primary_lan_ip():
    """Pick the first non-loopback IPv4 (server's LAN address)."""
    for name, ip in list_interfaces():
        if name != 'lo' and not ip.startswith('127.'):
            return ip
    return '127.0.0.1'

def setup_dnsmasq(domain, listen_ip):
    """Install + configure dnsmasq so LAN clients can resolve <domain> to
    this server's IP. Without this, Windows/macOS clients cannot reach
    textcord.local even if /etc/hosts on the server is correct."""
    server_ip = listen_ip if listen_ip not in ('0.0.0.0', '*') else _primary_lan_ip()
    if not shutil.which('dnsmasq'):
        try: pkg_install(['dnsmasq'])
        except Exception as e:
            print(f"  ! dnsmasq install failed ({e}); skipping LAN DNS setup.")
            return
    conf = (
        f"# Managed by textcord installer\n"
        f"address=/{domain}/{server_ip}\n"
        f"# Forward everything else to public DNS\n"
        f"server=1.1.1.1\nserver=8.8.8.8\n"
        f"# Don't read /etc/resolv.conf (avoid loops if systemd-resolved is on 53)\n"
        f"no-resolv\n"
        f"bind-interfaces\n"
    )
    os.makedirs('/etc/dnsmasq.d', exist_ok=True)
    with open('/etc/dnsmasq.d/textcord.conf', 'w') as f: f.write(conf)
    # On systems where systemd-resolved owns :53, free the port
    try:
        if shutil.which('systemctl'):
            subprocess.run(['systemctl', 'disable', '--now', 'systemd-resolved'],
                           capture_output=True)
    except Exception: pass
    run(['systemctl', 'enable', '--now', 'dnsmasq'], check=False)
    run(['systemctl', 'restart', 'dnsmasq'], check=False)
    print(f"  → dnsmasq resolves {domain} → {server_ip}")
    print(f"    Point LAN clients' DNS at {server_ip} (router DHCP or manual).")

def main():
    must_root()
    print(BANNER)
    print("  Welcome to the TextCord installer.\n")

    # 1. TLD
    tld = ask("Domain suffix", default="local", choices=["com", "pl", "org", "local"]).lower()
    domain = f"textcord.{tld}"
    print(f"  → host will be: {domain}\n")

    # 2. Interface
    ifs = list_interfaces()
    print("  Detected network interfaces:")
    for i, (name, ip) in enumerate(ifs):
        print(f"    [{i}] {name:10s}  {ip}")
    print(f"    [a] All interfaces (0.0.0.0)")
    sel = ask("Listen on which interface?", default="a")
    if sel.lower() == 'a': listen_ip = '0.0.0.0'
    else:
        try: listen_ip = ifs[int(sel)][1]
        except Exception: listen_ip = '0.0.0.0'
    print(f"  → listening IP: {listen_ip}\n")

    # 3. HSTS
    hsts = ask("Enable HSTS?", default="yes", choices=["yes", "no"]).lower() == 'yes'

    # 4. Cert name
    home = os.path.expanduser('~' + (os.environ.get('SUDO_USER') or ''))
    certs_dir = os.path.join(home, 'certs')
    cert_name = ask("Certificate name", default="textcord")

    install_app_files()
    ensure_deps()
    crt, key = gen_cert(cert_name, domain, certs_dir)

    # Local-name resolution: always update /etc/hosts on the server.
    ensure_hosts(domain)
    # LAN DNS for clients (Windows/macOS/phones) — required for textcord.<tld>.
    setup_dnsmasq(domain, listen_ip)

    write_conf(domain, hsts)
    write_nginx(domain, crt, key, hsts, listen_ip)
    write_service()
    wait_for_app()

    # Setup token
    token = secrets.token_urlsafe(60)[:80]
    write_token(token)

    url = f"https://{domain}/o/admin/{token}"
    print("\n" + "=" * 78)
    print("  ✔ Installation complete. Open this one-time link in your browser:")
    print()
    print(f"    {url}")
    print()
    print("  Use it to create the administrator account and configure registration.")
    print("  The link works only once and is destroyed after first successful setup.")
    print()
    print(f"  Certificate:  {crt}")
    print(f"  Config file:  {CONF_FILE}")
    print(f"  Autostart:    systemctl status textcord.service")
    print("=" * 78 + "\n")

if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt: print("\nAborted."); sys.exit(130)