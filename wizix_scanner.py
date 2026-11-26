# WIZIX local Windows security agent (read-only inventory)
import json, os, platform, subprocess, sys
from datetime import datetime
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
import threading, webbrowser

ROOT=Path(__file__).resolve().parent
HOST,PORT="127.0.0.1",8765

def ps_json(script, timeout=35):
    cmd=["powershell.exe","-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",script]
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,encoding="utf-8",errors="replace",
                     creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    if p.returncode!=0 and not p.stdout.strip():
        raise RuntimeError((p.stderr or "PowerShell command failed").strip()[:500])
    out=p.stdout.strip()
    if not out:return []
    try:return json.loads(out)
    except json.JSONDecodeError:return {"output":out[:4000]}

def run_scan():
    r={"generated":datetime.now().astimezone().isoformat(timespec="seconds"),
       "system":{"computer":platform.node(),"os":platform.platform(),"version":platform.version(),
                 "architecture":platform.machine(),"user":os.environ.get("USERNAME","unknown")}}
    r["apps"]=ps_json("$p=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); $x=foreach($k in $p){Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object @{n='name';e={$_.DisplayName}},@{n='version';e={$_.DisplayVersion}},@{n='publisher';e={$_.Publisher}},@{n='path';e={$_.InstallLocation}}}; @($x | Sort-Object name -Unique) | ConvertTo-Json -Depth 3 -Compress")
    r["processes"]=ps_json("Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object @{n='name';e={$_.Name}},@{n='detail';e={$_.ExecutablePath}},@{n='id';e={$_.ProcessId}},@{n='command';e={$_.CommandLine}} | ConvertTo-Json -Depth 3 -Compress")
    r["startup"]=ps_json("Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name,Command,Location,User | ConvertTo-Json -Depth 3 -Compress")
    r["security"]={}
    try:
        r["security"]["defender"]=ps_json("$s=Get-MpComputerStatus -ErrorAction Stop; [pscustomobject]@{AntivirusEnabled=$s.AntivirusEnabled;RealTimeProtectionEnabled=$s.RealTimeProtectionEnabled;AntispywareEnabled=$s.AntispywareEnabled;BehaviorMonitorEnabled=$s.BehaviorMonitorEnabled;IoavProtectionEnabled=$s.IoavProtectionEnabled;SignatureUpdated=($s.AntivirusSignatureLastUpdated -as [string]);QuickScanAge=$s.QuickScanAge;FullScanAge=$s.FullScanAge} | ConvertTo-Json -Compress",20)
    except Exception as e:r["security"]["defender"]={"error":str(e)}
    try:
        r["security"]["detections"]=ps_json("$d=@(Get-MpThreatDetection -ErrorAction Stop | Select-Object ThreatID,ThreatStatusID,ActionSuccess,InitialDetectionTime,LastThreatStatusChangeTime,Resources); @($d) | ConvertTo-Json -Depth 4 -Compress",20)
    except Exception as e:r["security"]["detections"]={"error":str(e)}
    try:
        r["security"]["firewall"]=ps_json("Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Depth 3 -Compress",20)
    except Exception as e:r["security"]["firewall"]={"error":str(e)}
    r["network"]=ps_json("Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue | Sort-Object State,LocalPort | Select-Object @{n='local';e={\"$($_.LocalAddress):$($_.LocalPort)\"}},@{n='remote';e={\"$($_.RemoteAddress):$($_.RemotePort)\"}},@{n='state';e={$_.State}},@{n='pid';e={$_.OwningProcess}} | ConvertTo-Json -Depth 3 -Compress")
    ex=[]
    roots=[("Chrome",Path(os.environ.get("LOCALAPPDATA",""))/"Google/Chrome/User Data"),
           ("Edge",Path(os.environ.get("LOCALAPPDATA",""))/"Microsoft/Edge/User Data")]
    for browser,root in roots:
        if not root.exists():continue
        try:
            for profile in list(root.iterdir())[:12]:
                folder=profile/"Extensions"
                if not folder.is_dir():continue
                for extid in list(folder.iterdir())[:150]:
                    if not extid.is_dir():continue
                    for ver in list(extid.iterdir())[:3]:
                        mf=ver/"manifest.json"
                        if mf.exists():
                            try:
                                m=json.loads(mf.read_text(encoding="utf-8"))
                                ex.append({"name":m.get("name","(unnamed)"),"detail":f"{browser} | {profile.name} | {extid.name} | version {m.get('version','?')}"})
                            except Exception:pass
        except Exception:pass
    r["extensions"]=ex
    return r

def list_directory(raw_path, limit=500):
    """Read-only directory inventory. The user explicitly chooses the folder."""
    if not raw_path:
        drives=[]
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            root=Path(f"{letter}:\\")
            if root.exists(): drives.append({"name":str(root),"path":str(root),"kind":"drive"})
        return {"path":"", "entries":drives, "count":len(drives), "truncated":False}
    target=Path(raw_path).expanduser()
    try: target=target.resolve(strict=True)
    except Exception as e: raise ValueError(f"Folder not found or inaccessible: {e}")
    if not target.is_dir(): raise ValueError("Selected path is not a folder")
    entries=[]
    try:
        with os.scandir(target) as it:
            for i,item in enumerate(it):
                if i>=limit: break
                try:
                    st=item.stat(follow_symlinks=False)
                    is_dir=item.is_dir(follow_symlinks=False)
                    entries.append({"name":item.name,"path":item.path,"kind":"folder" if is_dir else "file",
                                    "size":None if is_dir else st.st_size,
                                    "modified":datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(timespec="minutes"),
                                    "extension":Path(item.name).suffix.lower()})
                except (PermissionError, OSError):
                    entries.append({"name":item.name,"path":item.path,"kind":"unavailable","size":None,"modified":None,"extension":Path(item.name).suffix.lower()})
    except PermissionError as e: raise PermissionError(f"Access denied to folder: {target}") from e
    entries.sort(key=lambda x:(x["kind"]!="folder",x["name"].lower()))
    return {"path":str(target),"entries":entries,"count":len(entries),"truncated":len(entries)>=limit}

def defender_scan(kind):
    if kind not in ("quick","full"):raise ValueError("Invalid scan type")
    scan="QuickScan" if kind=="quick" else "FullScan"
    p=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",f"Start-MpScan -ScanType {scan} -ErrorAction Stop"],
                     capture_output=True,text=True,timeout=45,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    if p.returncode!=0:raise RuntimeError((p.stderr or p.stdout or "Defender did not accept scan request").strip()[:500])
    return {"ok":True,"message":"Microsoft Defender scan request submitted. Check Windows Security for progress and results.",
            "message_ar":"تم إرسال طلب الفحص إلى Microsoft Defender. تابع التقدم والنتيجة من أمن Windows."}

def url_check(raw):
    raw=(raw or "").strip()
    if len(raw)>2048:raise ValueError("URL is too long")
    u=urlparse(raw if "://" in raw else "https://"+raw)
    if u.scheme not in ("http","https") or not u.hostname:raise ValueError("Enter a valid http or https URL")
    host=u.hostname.lower();flags=[]
    if "@" in u.netloc:flags.append("URL contains user-info before host")
    if "xn--" in host:flags.append("Internationalized/punycode hostname")
    if host.replace(".","").isdigit():flags.append("Host appears to be an IP address")
    if len(host)>45:flags.append("Unusually long hostname")
    if host.count("-")>=3:flags.append("Hostname contains many hyphens")
    if u.scheme=="http":flags.append("Connection is not HTTPS")
    if any(k in (u.path+"?"+u.query).lower() for k in ("login","verify","password","wallet","update")):
        flags.append("Path/query contains commonly abused keywords (not proof of phishing)")
    return {"url":u.geturl(),"host":host,"flags":flags,"verdict":"review" if flags else "no_local_flags",
            "note":"Local heuristic only; it does not query threat intelligence and cannot certify a URL as safe."}

class Handler(SimpleHTTPRequestHandler):
    def __init__(self,*a,**kw):super().__init__(*a,directory=str(ROOT),**kw)
    def log_message(self,fmt,*args):print("[WIZIX]",fmt%args)
    def send_json(self,obj,status=200):
        b=json.dumps(obj,ensure_ascii=False).encode("utf-8")
        self.send_response(status);self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(b)));self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff");self.end_headers();self.wfile.write(b)
    def do_GET(self):
        parsed=urlparse(self.path)
        if parsed.path=="/api/health":return self.send_json({"ok":True,"agent":"WIZIX Windows Local Scanner","platform":platform.platform()})
        if parsed.path=="/api/scan":
            try:return self.send_json(run_scan())
            except Exception as e:
                print("[WIZIX][SCAN ERROR]",repr(e))
                return self.send_json({"error":str(e),"type":type(e).__name__},500)
        if parsed.path=="/api/files":
            try:
                q=parse_qs(parsed.query); raw=q.get("path",[""])[0]
                return self.send_json(list_directory(raw))
            except Exception as e:
                print("[WIZIX][FILES ERROR]",repr(e))
                return self.send_json({"error":str(e),"type":type(e).__name__},403 if isinstance(e,PermissionError) else 400)
        return super().do_GET()
    def do_POST(self):
        n=int(self.headers.get("Content-Length","0"))
        if n>10000:return self.send_json({"error":"Request too large"},413)
        try:data=json.loads(self.rfile.read(n) or b"{}")
        except Exception:return self.send_json({"error":"Invalid JSON"},400)
        if self.path=="/api/defender/scan":
            try:return self.send_json(defender_scan(data.get("type","quick")))
            except Exception as e:return self.send_json({"error":str(e)},500)
        if self.path=="/api/url-check":
            try:return self.send_json(url_check(data.get("url","")))
            except Exception as e:return self.send_json({"error":str(e)},400)
        return self.send_json({"error":"Not found"},404)

if __name__=="__main__":
    if os.name!="nt":
        print("WIZIX Windows Scanner requires Windows 10/11.");input("Press Enter to close.");sys.exit(1)
    srv=None
    for candidate in range(PORT,PORT+20):
        try:
            srv=ThreadingHTTPServer((HOST,candidate),Handler); PORT=candidate; break
        except OSError:
            continue
    if srv is None:
        print("Could not find a free local port (8765-8794). Close another WIZIX instance and try again.")
        input("Press Enter to close."); sys.exit(2)
    url=f"http://{HOST}:{PORT}"
    print(f"WIZIX Windows Scanner running at {url}")
    print("Local-only: not exposed to your Wi-Fi or other devices.")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:srv.serve_forever()
    except KeyboardInterrupt:pass
    finally:srv.server_close()
