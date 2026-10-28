/* PC Sentinel: built-in mock engine.
   Used when index.html still carries the literal token placeholder (opened without the engine) or the URL has ?mock=1.
   Serves every /api endpoint from in-memory state that actions really change (ack, kill, allow, blocklist, autostart…),
   and fakes the SSE stream: a metric every 2 s, a summary every 10 s, an occasional alert.

   Demo/test knobs (URL):
     &os=windows|macos|linux   platform of the fake engine (paths, processes, autostart kinds, coverage). Default windows.
     &setup=full|partial|none  coverage level (admin mode / root on, partial, nothing extra). Default partial.
     &xss=1                    adds hostile strings to every data type and defines PCS.xssSelfTest() for the console.
   Console: PCS.mock.setOffline(true) simulates the engine going away.

   Everything here is invented demo data: user "alex" on WORKSTATION-01, LAN 192.168.1.0/24, tailnet 100.64.0.0/10.
   Malicious addresses use the RFC 5737 documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x) only. */
(function () {
  'use strict';
  const PCS = (window.PCS = window.PCS || {});

  /* ------------------------------------------------------------------ helpers */
  function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const rand = mulberry32(0x5e172026);
  const rnd = (a, b) => a + rand() * (b - a);
  const rint = (a, b) => Math.floor(rnd(a, b + 1));
  const pick = (arr) => arr[Math.floor(rand() * arr.length)];
  const pad = (n) => String(n).padStart(2, '0');
  const iso = (msTime) => {
    const d = new Date(msTime);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };
  const T0 = Date.now();
  const ago = (sec) => iso(T0 - sec * 1000);
  const nowIso = () => iso(Date.now());
  const MIN = 60;
  const HOUR = 3600;
  const DAY = 86400;
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const win = (p) => p.replace(/\//g, '\\'); // Windows paths are written with "/" for readability
  const sleep = (msTime) => new Promise((r) => setTimeout(r, msTime));
  const smooth = (x) => { x = Math.max(0, Math.min(1, x)); return x * x * (3 - 2 * x); };

  const qs = new URLSearchParams(location.search);
  const OS = ['windows', 'macos', 'linux'].includes(qs.get('os')) ? qs.get('os') : 'windows';
  const SETUP = ['full', 'partial', 'none'].includes(qs.get('setup')) ? qs.get('setup') : 'partial';
  const XSS = qs.get('xss') === '1';
  const FILE_AUDIT = SETUP !== 'none';
  const FULL = SETUP === 'full';

  /* ------------------------------------------------------------------ demo identity (all invented) */
  const USER = 'alex';
  const HOST = 'WORKSTATION-01';
  const LAN_IP = '192.168.1.23';
  const LAN_GW = '192.168.1.1';
  const LAN_PEER = '192.168.1.40';
  const TS_IP = '100.64.0.7';
  const PEER = '100.64.0.12';
  const PEER_HOST = 'alex-laptop';
  const C2 = '203.0.113.66';
  const C2_PORT = 4444;
  const MAL_PID = 18736;
  const BOOT = 2 * DAY + 3 * HOUR + 17 * MIN;
  const ENGINE_UP = 3 * HOUR + 12 * MIN + 40;
  const CAM_AGO = 19 * DAY + 4 * HOUR + 12 * MIN; // camhelper's webcam use, long before the engine was installed

  /* XSS self-test payloads (only used with &xss=1) */
  const XP = {
    img: '<img src=x onerror=alert(1)>',
    host: '"><svg onload=alert(1)>',
    script: '<script>alert(1)</script>',
    attr: 'x" onmouseover="alert(1)',
    single: "' onfocus='alert(1)' autofocus='",
  };

  /* image table of the active profile: name -> [exe, signer, sig_status, trust] */
  let IMG = {};
  function ref(name, pid, exe) {
    const i = IMG[name] || ['', null, 'Unknown', 'known'];
    return { pid: pid === undefined ? null : pid, name, exe: exe || i[0], signer: i[1], sig_status: i[2], trust: i[3] };
  }

  /** Process-tree helper shared by the three profiles. */
  function treeBuilder(o) {
    const procs = [];
    const used = new Set(o.reserved || []);
    const newPid = () => {
      let p;
      do { p = o.pid(); } while (used.has(p));
      used.add(p);
      return p;
    };
    const add = (name, x) => {
      x = x || {};
      const img = IMG[name] || ['', null, 'Unknown', 'known'];
      const exe = x.exe !== undefined ? x.exe : img[0];
      const quote = o.quoteAlways || / /.test(exe);
      const p = {
        pid: x.pid !== undefined ? x.pid : newPid(), ppid: x.ppid || 0, parent: x.parent || null, name, exe,
        cmdline: x.cmd !== undefined ? x.cmd : exe ? (quote ? `"${exe}"` : exe) : '',
        user: x.user || USER, started: ago(x.age !== undefined ? x.age : rint(BOOT - 900, BOOT - 30)),
        signer: x.signer !== undefined ? x.signer : img[1], sig_status: img[2], trust: img[3],
        cpu: 0, mem_mb: x.mem !== undefined ? x.mem : rint(3, 28), net_conns: 0, flags: x.flags || [],
        _cpu: x.cpu !== undefined ? x.cpu : 0.02,
      };
      if (x.pid !== undefined) used.add(x.pid);
      procs.push(p);
      return p;
    };
    const child = (parent, name, x) => add(name, Object.assign({ ppid: parent.pid, parent: parent.name }, x || {}));
    return { procs, add, child };
  }

  function mkConn(proc, raddr, rport, rhost, o) {
    o = o || {};
    return {
      pid: proc.pid, process: proc.name, exe: proc.exe, signer: proc.signer, trust: proc.trust,
      proto: o.proto || 'TCP', laddr: o.laddr || LAN_IP, lport: o.lport || rint(49800, 65200),
      raddr, rport, rhost: rhost || null, status: o.status || (o.proto === 'UDP' ? 'NONE' : 'ESTABLISHED'),
      direction: o.dir || 'out', first_seen: ago(o.age !== undefined ? o.age : rint(30, 3 * HOUR)), flags: o.flags || [],
    };
  }
  const mkListen = (proc, proto, laddr, lport, age) => ({
    proto, laddr, lport, pid: proc.pid, process: proc.name, exe: proc.exe, trust: proc.trust,
    exposed: laddr === '0.0.0.0' || laddr === '::', first_seen: ago(age || rint(BOOT - 600, BOOT)),
  });
  function A(id, sev, cat, title, summary, o) {
    const first = o.first !== undefined ? o.first : o.last;
    return {
      id, ts: ago(o.last), first_ts: ago(first), last_ts: ago(o.last), count: o.count || 1,
      severity: sev, category: cat, title, summary, process: o.process || null, remote: o.remote || null,
      details: o.details || {}, status: o.status || 'open',
    };
  }
  const mkPersist = (kind, location, name, command, exe, signer, sig, trust, status, firstSec, flags) => ({
    kind, location, name, command, exe, signer, sig_status: sig, trust, status, first_seen: ago(firstSec), last_seen: ago(rint(5, 120)), flags: flags || [],
  });

  /* ================================================================== profile: Windows */
  function windowsProfile() {
    const S32 = 'C:/Windows/System32/';
    const MSW = 'Microsoft Windows';
    const MSC = 'Microsoft Corporation';
    const EDGE = win('C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe');
    const CHROME = win('C:/Program Files/Google/Chrome/Application/chrome.exe');
    const SLACK = win('C:/Users/alex/AppData/Local/slack/app-4.41.105/slack.exe');
    const ZOOM = win('C:/Users/alex/AppData/Roaming/Zoom/bin/Zoom.exe');
    const STEAM = win('C:/Program Files (x86)/Steam/steam.exe');
    const SPOTIFY = win('C:/Users/alex/AppData/Roaming/Spotify/Spotify.exe');
    const CODE = win('C:/Users/alex/AppData/Local/Programs/Microsoft VS Code/Code.exe');
    const TELEGRAM = win('C:/Users/alex/AppData/Roaming/Telegram Desktop/Telegram.exe');
    const YTDLP = win('C:/Users/alex/Tools/yt-dlp.exe');
    const UPDSVC = win('C:/ProgramData/{8C2E41D7-5B3A-4F19-A6D2-0E7C93B1F4A8}/updsvc.exe');
    const CAMHELPER = win('C:/Users/alex/.cache/.sys/camhelper.exe');
    const VENV_PY = win('C:/Users/alex/src/pc-sentinel/.venv/Scripts/python.exe');
    const SYS_PY = win('C:/Users/alex/AppData/Local/Programs/Python/Python312/python.exe');
    const NODE = win('C:/Program Files/nodejs/node.exe');
    const SSHD = win(`${S32}OpenSSH/sshd.exe`);
    const DEF_DIR = 'C:/ProgramData/Microsoft/Windows Defender/Platform/4.18.25090.3009-0/';
    const TERM_DIR = 'C:/Program Files/WindowsApps/Microsoft.WindowsTerminal_1.23.12811.0_x64__8wekyb3d8bbwe/';
    const HOME = 'C:\\Users\\alex\\';

    const img = {
      'System': ['', MSW, 'Valid', 'trusted'],
      'Registry': ['', MSW, 'Valid', 'trusted'],
      'smss.exe': [`${S32}smss.exe`, MSW, 'Valid', 'trusted'],
      'csrss.exe': [`${S32}csrss.exe`, MSW, 'Valid', 'trusted'],
      'wininit.exe': [`${S32}wininit.exe`, MSW, 'Valid', 'trusted'],
      'services.exe': [`${S32}services.exe`, MSW, 'Valid', 'trusted'],
      'lsass.exe': [`${S32}lsass.exe`, MSW, 'Valid', 'trusted'],
      'winlogon.exe': [`${S32}winlogon.exe`, MSW, 'Valid', 'trusted'],
      'svchost.exe': [`${S32}svchost.exe`, MSW, 'Valid', 'trusted'],
      'fontdrvhost.exe': [`${S32}fontdrvhost.exe`, MSW, 'Valid', 'trusted'],
      'dwm.exe': [`${S32}dwm.exe`, MSW, 'Valid', 'trusted'],
      'spoolsv.exe': [`${S32}spoolsv.exe`, MSW, 'Valid', 'trusted'],
      'explorer.exe': ['C:/Windows/explorer.exe', MSW, 'Valid', 'trusted'],
      'sihost.exe': [`${S32}sihost.exe`, MSW, 'Valid', 'trusted'],
      'taskhostw.exe': [`${S32}taskhostw.exe`, MSW, 'Valid', 'trusted'],
      'RuntimeBroker.exe': [`${S32}RuntimeBroker.exe`, MSW, 'Valid', 'trusted'],
      'ctfmon.exe': [`${S32}ctfmon.exe`, MSW, 'Valid', 'trusted'],
      'conhost.exe': [`${S32}conhost.exe`, MSW, 'Valid', 'trusted'],
      'audiodg.exe': [`${S32}audiodg.exe`, MSW, 'Valid', 'trusted'],
      'WmiPrvSE.exe': [`${S32}wbem/WmiPrvSE.exe`, MSW, 'Valid', 'trusted'],
      'dllhost.exe': [`${S32}dllhost.exe`, MSW, 'Valid', 'trusted'],
      'SecurityHealthService.exe': [`${S32}SecurityHealthService.exe`, MSW, 'Valid', 'trusted'],
      'SecurityHealthSystray.exe': [`${S32}SecurityHealthSystray.exe`, MSW, 'Valid', 'trusted'],
      'powershell.exe': [`${S32}WindowsPowerShell/v1.0/powershell.exe`, MSW, 'Valid', 'trusted'],
      'sshd.exe': [SSHD, MSW, 'Valid', 'trusted'],
      'winget.exe': ['C:/Users/alex/AppData/Local/Microsoft/WindowsApps/winget.exe', MSC, 'Valid', 'trusted'],
      'SearchHost.exe': ['C:/Windows/SystemApps/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/SearchHost.exe', MSC, 'Valid', 'trusted'],
      'StartMenuExperienceHost.exe': ['C:/Windows/SystemApps/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/StartMenuExperienceHost.exe', MSC, 'Valid', 'trusted'],
      'ShellExperienceHost.exe': ['C:/Windows/SystemApps/ShellExperienceHost_cw5n1h2txyewy/ShellExperienceHost.exe', MSC, 'Valid', 'trusted'],
      'TextInputHost.exe': ['C:/Windows/SystemApps/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/TextInputHost.exe', MSC, 'Valid', 'trusted'],
      'MsMpEng.exe': [`${DEF_DIR}MsMpEng.exe`, MSC, 'Valid', 'trusted'],
      'NisSrv.exe': [`${DEF_DIR}NisSrv.exe`, MSC, 'Valid', 'trusted'],
      'igfxEM.exe': [`${S32}DriverStore/FileRepository/iigd_dch.inf_amd64_1f0c2b7e9a4d6c35/igfxEM.exe`, 'Intel(R) pGFX', 'Valid', 'trusted'],
      'RtkAudUService64.exe': [`${S32}DriverStore/FileRepository/realtekservice.inf_amd64_7d3e91a0c4b2f586/RtkAudUService64.exe`, 'Realtek Semiconductor Corp.', 'Valid', 'trusted'],
      'msedge.exe': [EDGE, MSC, 'Valid', 'trusted'],
      'msedgewebview2.exe': ['C:/Program Files (x86)/Microsoft/EdgeWebView/Application/141.0.3537.71/msedgewebview2.exe', MSC, 'Valid', 'trusted'],
      'chrome.exe': [CHROME, 'Google LLC', 'Valid', 'trusted'],
      'slack.exe': [SLACK, 'Slack Technologies, LLC', 'Valid', 'trusted'],
      'Zoom.exe': [ZOOM, 'Zoom Video Communications, Inc.', 'Valid', 'trusted'],
      'steam.exe': [STEAM, 'Valve Corp.', 'Valid', 'trusted'],
      'steamwebhelper.exe': ['C:/Program Files (x86)/Steam/bin/cef/cef.win7x64/steamwebhelper.exe', 'Valve Corp.', 'Valid', 'trusted'],
      'Spotify.exe': [SPOTIFY, 'Spotify AB', 'Valid', 'trusted'],
      'Code.exe': [CODE, MSC, 'Valid', 'trusted'],
      'Telegram.exe': [TELEGRAM, 'Telegram FZ-LLC', 'Valid', 'trusted'],
      'yt-dlp.exe': [YTDLP, null, 'NotSigned', 'unsigned'],
      'node.exe': [NODE, 'OpenJS Foundation', 'Valid', 'trusted'],
      'python.exe': [VENV_PY, 'Python Software Foundation', 'Valid', 'known'],
      'tailscaled.exe': ['C:/Program Files/Tailscale/tailscaled.exe', 'Tailscale Inc.', 'Valid', 'trusted'],
      'tailscale-ipn.exe': ['C:/Program Files/Tailscale/tailscale-ipn.exe', 'Tailscale Inc.', 'Valid', 'trusted'],
      'WindowsTerminal.exe': [`${TERM_DIR}WindowsTerminal.exe`, MSC, 'Valid', 'trusted'],
      'OpenConsole.exe': [`${TERM_DIR}OpenConsole.exe`, MSC, 'Valid', 'trusted'],
      'pwsh.exe': ['C:/Program Files/PowerShell/7/pwsh.exe', MSC, 'Valid', 'trusted'],
      'updsvc.exe': [UPDSVC, 'Contoso Software Ltd.', 'HashMismatch', 'malicious'],
    };
    Object.values(img).forEach((v) => { v[0] = win(v[0]); });

    const SVC_GROUPS = [
      '-k DcomLaunch -p', '-k RPCSS -p', '-k RPCSS -p -s RpcEptMapper', '-k LocalServiceNoNetworkFirewall -p',
      '-k netsvcs -p -s Schedule', '-k netsvcs -p -s Winmgmt', '-k LocalServiceNetworkRestricted -p -s EventLog',
      '-k NetworkService -p -s Dnscache', '-k NetworkService -p -s DoSvc', '-k netsvcs -p -s wuauserv',
      '-k LocalSystemNetworkRestricted -p -s SysMain', '-k UnistackSvcGroup -s WpnUserService_4f2a9', '-k LocalService -p -s CDPSvc',
      '-k netsvcs -p -s BITS', '-k LocalServiceNetworkRestricted -p -s Dhcp', '-k netsvcs -p -s UserManager',
      '-k LocalServiceNoNetwork -p -s DPS', '-k appmodel -p -s StateRepository', '-k netsvcs -p -s Themes',
      '-k LocalSystemNetworkRestricted -p -s AudioEndpointBuilder', '-k LocalServiceNetworkRestricted -p -s Audiosrv',
      '-k netsvcs -p -s ShellHWDetection', '-k netsvcs -p -s iphlpsvc', '-k LocalService -s W32Time',
      '-k NetworkService -s LanmanWorkstation', '-k netsvcs -p -s LanmanServer', '-k LocalServiceNetworkRestricted -p -s WinHttpAutoProxySvc',
      '-k ClipboardSvcGroup -p -s cbdhsvc_4f2a9', '-k netsvcs -p -s CertPropSvc', '-k LocalSystemNetworkRestricted -p -s TrkWks',
      '-k netsvcs -p -s ProfSvc', '-k wsappx -p -s AppXSvc', '-k LocalService -p -s FontCache', '-k camera -s FrameServer',
      '-k LocalSystemNetworkRestricted -p -s PcaSvc', '-k netsvcs -p -s SENS', '-k utcsvc -p', '-k LocalService -p -s BthAvctpSvc',
      '-k netsvcs -p -s WpnService', '-k netsvcs -p -s lfsvc', '-k LocalService -p -s DispBrokerDesktopSvc', '-k netsvcs -p -s TokenBroker',
      '-k UnistackSvcGroup -s CDPUserSvc_4f2a9', '-k LocalServiceNetworkRestricted -p -s lmhosts', '-k NetworkService -p -s NlaSvc',
      '-k LocalService -p -s nsi', '-k netsvcs -p -s SessionEnv', '-k LocalServiceNoNetworkFirewall -p -s mpssvc',
      '-k LocalService -p -s EventSystem', '-k netsvcs -p -s gpsvc', '-k LocalSystemNetworkRestricted -p -s StorSvc',
      '-k NetworkService -p -s CryptSvc', '-k LocalServiceAndNoImpersonation -p -s SSDPSRV', '-k LocalServiceAndNoImpersonation -p -s FDResPub',
      '-k netsvcs -p -s DsmSvc', '-k LocalSystemNetworkRestricted -p -s hidserv', '-k netsvcs -p -s Appinfo', '-k LocalService -p -s TimeBrokerSvc',
    ];
    const svcUser = (g) => (/_4f2a9/.test(g) ? USER : /NetworkService|RPCSS/.test(g) ? 'NETWORK SERVICE' : /LocalService|camera/.test(g) ? 'LOCAL SERVICE' : 'SYSTEM');
    const chromium = (exe, type, extra) => `"${exe}" --type=${type} ${extra ? `${extra} ` : ''}--lang=en-US --field-trial-handle=${rint(1800, 2400)},i,${rint(100000000, 999999999)}${rint(100000000, 999999999)},${rint(100000000, 999999999)},262144 --mojo-platform-channel-handle=${rint(2000, 9800)} /prefetch:${pick([1, 2, 3, 5, 8, 11])}`;

    function buildProcesses() {
      const { procs, add, child } = treeBuilder({ reserved: [4, 180, 5212, MAL_PID, 7744], pid: () => rint(160, 8400) * 4, quoteAlways: true });
      const P = {};
      const system = add('System', { pid: 4, user: 'SYSTEM', age: BOOT, mem: 0.2, cmd: '', cpu: 0.6 });
      child(system, 'Registry', { pid: 180, user: 'SYSTEM', age: BOOT, mem: 48, cmd: '' });
      child(system, 'smss.exe', { user: 'SYSTEM', age: BOOT, mem: 1.1, cmd: '\\SystemRoot\\System32\\smss.exe' });
      const csrssCmd = '%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16';
      add('csrss.exe', { user: 'SYSTEM', age: BOOT, mem: 5, cmd: csrssCmd, ppid: 708 });
      add('csrss.exe', { user: 'SYSTEM', age: BOOT - 40, mem: 7, cmd: csrssCmd, ppid: 812, cpu: 0.2 });
      const wininit = add('wininit.exe', { user: 'SYSTEM', age: BOOT, mem: 6, cmd: 'wininit.exe', ppid: 708 });
      const services = child(wininit, 'services.exe', { user: 'SYSTEM', age: BOOT, mem: 10, cmd: 'C:\\Windows\\system32\\services.exe', cpu: 0.05 });
      P.lsass = child(wininit, 'lsass.exe', { user: 'SYSTEM', age: BOOT, mem: 26, cmd: 'C:\\Windows\\system32\\lsass.exe', cpu: 0.08 });
      const winlogon = add('winlogon.exe', { user: 'SYSTEM', age: BOOT - 40, mem: 11, cmd: 'winlogon.exe', ppid: 812 });
      child(wininit, 'fontdrvhost.exe', { user: 'UMFD-0', age: BOOT, mem: 3, cmd: '"fontdrvhost.exe"' });
      child(winlogon, 'fontdrvhost.exe', { user: 'UMFD-1', age: BOOT - 40, mem: 9, cmd: '"fontdrvhost.exe"' });
      child(winlogon, 'dwm.exe', { user: 'DWM-1', age: BOOT - 40, mem: 152, cpu: 1.6, cmd: '"dwm.exe"' });

      P.svc = {};
      SVC_GROUPS.forEach((g) => {
        const name = (g.match(/-s (\S+)/) || g.match(/-k (\S+)/))[1];
        P.svc[name] = child(services, 'svchost.exe', {
          user: svcUser(g), age: rint(BOOT - 600, BOOT - 5), mem: rint(3, 36), cmd: `C:\\Windows\\system32\\svchost.exe ${g}`,
          cpu: /DcomLaunch|Winmgmt|Audiosrv|SysMain|EventLog/.test(g) ? 0.25 : 0.02,
        });
      });
      const dcom = P.svc.DcomLaunch;
      child(services, 'spoolsv.exe', { user: 'SYSTEM', mem: 14, cmd: 'C:\\Windows\\System32\\spoolsv.exe' });
      child(P.svc.Audiosrv, 'audiodg.exe', { user: 'LOCAL SERVICE', age: 34 * MIN, mem: 18, cpu: 0.6, cmd: 'C:\\Windows\\system32\\AUDIODG.EXE 0x52c' });
      P.defender = child(services, 'MsMpEng.exe', { user: 'SYSTEM', mem: 318, cpu: 0.9 });
      child(services, 'NisSrv.exe', { user: 'LOCAL SERVICE', mem: 12 });
      child(services, 'SecurityHealthService.exe', { user: 'SYSTEM', mem: 9 });
      child(services, 'RtkAudUService64.exe', { user: 'SYSTEM', mem: 7, cmd: `"${img['RtkAudUService64.exe'][0]}" -background` });
      P.sshd = child(services, 'sshd.exe', { user: 'SYSTEM', age: BOOT - 25, mem: 6, cmd: `"${SSHD}"` });
      P.sshSess = child(P.sshd, 'sshd.exe', { user: 'SYSTEM', age: 24 * MIN, mem: 8, cpu: 0.1, cmd: `"${SSHD}" -z` });

      const explorer = add('explorer.exe', { pid: 5212, ppid: 7744, age: BOOT - 95, mem: 188, cpu: 0.35, cmd: 'C:\\WINDOWS\\Explorer.EXE' });
      child(P.svc.ProfSvc || services, 'sihost.exe', { age: BOOT - 100, mem: 24, cmd: 'sihost.exe' });
      child(P.svc.Schedule, 'taskhostw.exe', { age: BOOT - 98, mem: 14, cmd: 'taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}' });
      child(P.svc.Schedule, 'taskhostw.exe', { age: 4 * HOUR, mem: 9, cmd: 'taskhostw.exe Install $(Arg0)' });
      child(services, 'ctfmon.exe', { age: BOOT - 96, mem: 15, cmd: '"ctfmon.exe"' });
      for (let i = 0; i < 9; i++) child(dcom, 'RuntimeBroker.exe', { mem: rint(5, 32), cmd: 'C:\\Windows\\System32\\RuntimeBroker.exe -Embedding', age: rint(10 * MIN, BOOT - 100) });
      const search = child(dcom, 'SearchHost.exe', { mem: 96, cmd: `"${img['SearchHost.exe'][0]}" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca` });
      child(dcom, 'StartMenuExperienceHost.exe', { mem: 71, cmd: `"${img['StartMenuExperienceHost.exe'][0]}" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca` });
      child(dcom, 'ShellExperienceHost.exe', { mem: 58, cmd: `"${img['ShellExperienceHost.exe'][0]}" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca` });
      child(dcom, 'TextInputHost.exe', { mem: 44, cmd: `"${img['TextInputHost.exe'][0]}" -ServerName:InputApp.AppXjd5de1g66v206tj52m9d0dtpppx4cgpn.mca` });
      for (let i = 0; i < 3; i++) child(dcom, 'WmiPrvSE.exe', { user: i ? 'NETWORK SERVICE' : 'SYSTEM', mem: rint(8, 22), cmd: 'C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding' });
      for (let i = 0; i < 3; i++) child(dcom, 'dllhost.exe', { mem: rint(6, 14), cmd: 'C:\\Windows\\system32\\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}' });
      for (let i = 0; i < 6; i++) child(search, 'msedgewebview2.exe', { mem: rint(18, 120), cmd: chromium(img['msedgewebview2.exe'][0], i ? 'renderer' : 'gpu-process', '--webview-exe-name=SearchHost.exe') });
      child(explorer, 'SecurityHealthSystray.exe', { age: BOOT - 90, mem: 8 });
      child(explorer, 'igfxEM.exe', { age: BOOT - 90, mem: 12 });

      // Edge: browser + network service + gpu + renderers (all sockets live in the network-service utility process)
      const edge = P.edge = child(explorer, 'msedge.exe', { age: 5 * HOUR + 12 * MIN, mem: 214, cpu: 0.6, cmd: `"${EDGE}" --profile-directory=Default` });
      P.edgeNet = child(edge, 'msedge.exe', { age: 5 * HOUR + 12 * MIN, mem: 48, cpu: 0.5, cmd: chromium(EDGE, 'utility', '--utility-sub-type=network.mojom.NetworkService --service-sandbox-type=none') });
      child(edge, 'msedge.exe', { age: 5 * HOUR + 12 * MIN, mem: 268, cpu: 2.8, cmd: chromium(EDGE, 'gpu-process') });
      child(edge, 'msedge.exe', { age: 5 * HOUR + 12 * MIN, mem: 7, cmd: `"${EDGE}" --type=crashpad-handler --user-data-dir=${HOME}AppData\\Local\\Microsoft\\Edge\\User Data /prefetch:4` });
      for (let i = 0; i < 18; i++) {
        child(edge, 'msedge.exe', {
          age: rint(2 * MIN, 5 * HOUR), mem: rint(36, 420), cpu: i === 0 ? 3.2 : pick([0.02, 0.05, 0.1, 0.3]),
          cmd: chromium(EDGE, 'renderer', `--device-scale-factor=1.25 --num-raster-threads=4 --renderer-client-id=${12 + i * 3}`),
        });
      }
      const chrome = P.chrome = child(explorer, 'chrome.exe', { age: BOOT - 85, mem: 196, cpu: 0.3, cmd: `"${CHROME}" --profile-directory=Default` });
      P.chromeNet = child(chrome, 'chrome.exe', { age: BOOT - 85, mem: 41, cpu: 0.2, cmd: chromium(CHROME, 'utility', '--utility-sub-type=network.mojom.NetworkService --service-sandbox-type=none') });
      child(chrome, 'chrome.exe', { age: BOOT - 85, mem: 181, cpu: 0.9, cmd: chromium(CHROME, 'gpu-process') });
      for (let i = 0; i < 12; i++) child(chrome, 'chrome.exe', { age: rint(10 * MIN, BOOT - 90), mem: rint(30, 260), cpu: pick([0.02, 0.05, 0.1]), cmd: chromium(CHROME, 'renderer', `--renderer-client-id=${7 + i * 2}`) });

      const slack = P.slack = child(explorer, 'slack.exe', { age: BOOT - 84, mem: 220, cpu: 0.4, cmd: `"${SLACK}" --process-start-args --startup` });
      P.slackNet = child(slack, 'slack.exe', { age: BOOT - 84, mem: 39, cpu: 0.3, cmd: chromium(SLACK, 'utility', '--utility-sub-type=network.mojom.NetworkService') });
      child(slack, 'slack.exe', { age: BOOT - 84, mem: 150, cpu: 0.6, cmd: chromium(SLACK, 'gpu-process') });
      for (let i = 0; i < 3; i++) child(slack, 'slack.exe', { age: BOOT - 83, mem: rint(120, 380), cpu: i ? 0.1 : 0.9, cmd: chromium(SLACK, 'renderer', `--renderer-client-id=${5 + i}`) });

      P.zoom = child(explorer, 'Zoom.exe', { age: 36 * MIN, mem: 310, cpu: 6.2, cmd: `"${ZOOM}" --action=join --confno=0000000000` });
      P.steam = child(explorer, 'steam.exe', { age: BOOT - 80, mem: 142, cpu: 0.4, cmd: `"${STEAM}" -silent` });
      for (let i = 0; i < 3; i++) child(P.steam, 'steamwebhelper.exe', { age: BOOT - 79, mem: rint(40, 160), cmd: `"${img['steamwebhelper.exe'][0]}" -lang=en_US -cachedir=C:\\Users\\alex\\AppData\\Local\\Steam\\htmlcache --type=${i ? 'renderer' : 'gpu-process'}` });
      P.spotify = child(explorer, 'Spotify.exe', { age: 2 * HOUR + 6 * MIN, mem: 260, cpu: 1.1, cmd: `"${SPOTIFY}" --autostart --minimized` });
      for (let i = 0; i < 3; i++) child(P.spotify, 'Spotify.exe', { age: 2 * HOUR + 6 * MIN, mem: rint(60, 200), cmd: chromium(SPOTIFY, i ? 'renderer' : 'gpu-process') });
      P.telegram = child(explorer, 'Telegram.exe', { age: BOOT - 82, mem: 214, cpu: 0.2, cmd: `"${TELEGRAM}" -autostart` });
      P.code = child(explorer, 'Code.exe', { age: 6 * HOUR + 3 * MIN, mem: 280, cpu: 0.8 });
      for (let i = 0; i < 4; i++) child(P.code, 'Code.exe', { age: 6 * HOUR + 2 * MIN, mem: rint(80, 520), cpu: i ? 0.2 : 1.4, cmd: chromium(CODE, i === 3 ? 'utility' : 'renderer', i === 3 ? '--utility-sub-type=node.mojom.NodeService' : '') });
      child(explorer, 'tailscale-ipn.exe', { age: BOOT - 88, mem: 21 });
      P.tailscaled = child(services, 'tailscaled.exe', { user: 'SYSTEM', age: BOOT - 20, mem: 49, cpu: 0.1 });

      const wt = child(explorer, 'WindowsTerminal.exe', { age: 3 * HOUR + 20 * MIN, mem: 88, cpu: 0.2 });
      const pwsh1 = child(wt, 'pwsh.exe', { age: 3 * HOUR + 20 * MIN, mem: 74, cmd: '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -NoLogo' });
      const pwsh2 = child(wt, 'pwsh.exe', { age: 58 * MIN, mem: 69, cmd: '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -NoLogo' });
      child(wt, 'OpenConsole.exe', { age: 3 * HOUR + 20 * MIN, mem: 9 });
      child(wt, 'OpenConsole.exe', { age: 58 * MIN, mem: 9 });
      P.engine = child(pwsh1, 'python.exe', { age: ENGINE_UP, mem: 76, cpu: 0.9, cmd: `"${VENV_PY}" main.py --port 8777` });
      P.httpd = child(pwsh2, 'python.exe', { age: 41 * MIN, mem: 22, cmd: `"${VENV_PY}" -m http.server 8790 --bind 127.0.0.1 --directory "${HOME}src\\pc-sentinel\\dashboard"` });
      P.pip = child(pwsh2, 'python.exe', { exe: SYS_PY, age: 53 * MIN, mem: 214, cpu: 0.4, cmd: `"${SYS_PY}" -m pip install --upgrade torch torchvision` });
      P.dev = child(pwsh1, 'node.exe', { age: 2 * HOUR + 44 * MIN, mem: 118, cpu: 0.2, cmd: `"${NODE}" "${HOME}src\\webapp\\node_modules\\next\\dist\\bin\\next" dev -H 0.0.0.0 -p 3000` });
      P.npm = child(pwsh1, 'node.exe', { age: 66 * MIN, mem: 92, cpu: 0.1, cmd: `"${NODE}" "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js" install` });
      P.ytdlp = child(pwsh2, 'yt-dlp.exe', { age: 2 * HOUR + 5 * MIN, mem: 64, cpu: 0.6, flags: ['unsigned', 'user_writable_path'], cmd: `"${YTDLP}" -x --audio-format mp3 https://www.youtube.com/watch?v=aqz-KE-bpKQ` });
      P.ps = child(pwsh2, 'powershell.exe', {
        age: 25 * MIN, mem: 61, cpu: 0.1, flags: ['lolbin'],
        cmd: 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile $env:TEMP\\winget.msixbundle"',
      });
      child(P.ps, 'conhost.exe', { age: 25 * MIN, mem: 6, cmd: '\\??\\C:\\Windows\\system32\\conhost.exe 0x4' });
      child(P.ps, 'winget.exe', { age: 24 * MIN, mem: 34, cmd: 'winget.exe upgrade --all --include-unknown' });

      P.mal = child(explorer, 'updsvc.exe', {
        pid: MAL_PID, age: 47 * MIN, mem: 23, cpu: 0.1, cmd: `"${UPDSVC}" /auto`,
        flags: ['sig_mismatch', 'padded_binary', 'user_writable_path'],
      });
      return { procs, P };
    }

    function buildConnections(P) {
      const c = [];
      [
        ['13.107.42.14', 443, 'edge.microsoft.com'], ['204.79.197.200', 443, 'www.bing.com'], ['142.250.185.78', 443, 'meet.google.com'],
        ['172.217.19.110', 443, 'mail.google.com'], ['140.82.114.26', 443, 'alive.github.com'], ['151.101.1.140', 443, 'www.reddit.com'],
        ['20.190.159.68', 443, 'login.microsoftonline.com'], ['52.123.128.14', 443, 'substrate.office.com'], ['23.212.249.8', 443, 'www.microsoft.com'],
        ['216.58.212.10', 443, 'fonts.googleapis.com'], ['142.250.200.3', 443, 'www.gstatic.com'], ['104.18.32.47', 443, 'github.githubassets.com'],
      ].forEach(([ip, port, host]) => c.push(mkConn(P.edgeNet, ip, port, host)));
      [
        ['142.250.181.206', 443, 'www.google.com'], ['142.250.187.238', 443, 'accounts.google.com'], ['142.250.181.238', 443, 'www.youtube.com'],
        ['142.250.181.238', 443, 'www.youtube.com'], ['142.250.186.46', 443, 'docs.google.com'], ['151.101.193.69', 443, 'stackoverflow.com'],
      ].forEach(([ip, port, host]) => c.push(mkConn(P.chromeNet, ip, port, host)));
      [
        ['52.29.238.212', 443, 'wss-primary.slack.com'], ['18.66.218.31', 443, 'edgeapi.slack.com'], ['18.66.218.31', 443, 'app.slack.com'],
        ['35.157.212.10', 443, 'files.slack.com'], ['23.53.40.162', 443, 'a.slack-edge.com'],
      ].forEach(([ip, port, host]) => c.push(mkConn(P.slackNet, ip, port, host, { age: rint(10 * MIN, BOOT - 90) })));
      c.push(mkConn(P.zoom, '170.114.52.2', 443, 'zoom.us', { age: 36 * MIN }));
      c.push(mkConn(P.zoom, '170.114.10.86', 8801, null, { proto: 'UDP', age: 34 * MIN }));
      c.push(mkConn(P.zoom, '170.114.10.86', 443, null, { age: 34 * MIN }));
      c.push(mkConn(P.telegram, '149.154.167.51', 443, null));
      c.push(mkConn(P.telegram, '149.154.167.41', 443, null));
      c.push(mkConn(P.telegram, '149.154.175.53', 443, null, { age: 2 * HOUR }));
      c.push(mkConn(P.code, '13.107.42.18', 443, 'marketplace.visualstudio.com', { age: 6 * HOUR }));
      c.push(mkConn(P.code, '140.82.112.21', 443, 'api.github.com', { age: 5 * HOUR }));
      c.push(mkConn(P.code, '20.42.65.92', 443, 'mobile.events.data.microsoft.com', { age: 4 * HOUR }));
      c.push(mkConn(P.steam, '23.36.163.47', 443, 'steamcommunity.com', { age: BOOT - 80 }));
      c.push(mkConn(P.steam, '162.254.197.39', 27019, null, { age: BOOT - 80 }));
      c.push(mkConn(P.steam, LAN_PEER, 27036, null, { age: 3 * HOUR, flags: ['odd_port'] }));
      c.push(mkConn(P.spotify, '35.186.224.25', 443, 'spclient.wg.spotify.com', { age: 2 * HOUR }));
      c.push(mkConn(P.spotify, '104.199.65.124', 4070, 'ap-gew4.spotify.com', { age: 2 * HOUR }));
      c.push(mkConn(P.ytdlp, '142.250.181.238', 443, 'www.youtube.com', { flags: ['unsigned'], age: 2 * HOUR + 5 * MIN }));
      c.push(mkConn(P.ytdlp, '173.194.182.70', 443, 'rr3---sn-4g5e6nsz.googlevideo.com', { flags: ['unsigned'], age: 2 * HOUR + 4 * MIN }));
      c.push(mkConn(P.dev, '140.82.113.3', 443, 'github.com', { status: 'TIME_WAIT' }));
      c.push(mkConn(P.npm, '104.16.30.34', 443, 'registry.npmjs.org', { age: 65 * MIN }));
      c.push(mkConn(P.pip, '151.101.64.223', 443, 'files.pythonhosted.org', { age: 52 * MIN }));
      c.push(mkConn(P.pip, '151.101.0.223', 443, 'pypi.org', { status: 'CLOSE_WAIT', age: 53 * MIN }));
      c.push(mkConn(P.tailscaled, '18.196.164.18', 443, 'controlplane.tailscale.com', { age: BOOT - 20 }));
      c.push(mkConn(P.tailscaled, '46.101.98.215', 443, 'derp4.tailscale.com', { age: BOOT - 20 }));
      c.push(mkConn(P.sshSess, PEER, 52731, PEER_HOST, { laddr: TS_IP, lport: 22, dir: 'in', age: 24 * MIN }));
      c.push(mkConn(P.svc.DoSvc, '13.107.4.50', 80, 'tlu.dl.delivery.mp.microsoft.com', { status: 'TIME_WAIT' }));
      c.push(mkConn(P.svc.wuauserv, '20.42.65.85', 443, 'fe3cr.delivery.mp.microsoft.com'));
      c.push(mkConn(P.svc.WpnService, '20.199.120.85', 443, 'client.wns.windows.com', { age: BOOT - 60 }));
      c.push(mkConn(P.defender, '20.31.6.157', 443, 'wdcp.microsoft.com'));
      c.push(mkConn(P.ps, '23.53.33.84', 443, 'aka.ms', { flags: ['lolbin'], age: 25 * MIN }));
      c.push(mkConn(P.mal, C2, C2_PORT, null, { status: 'SYN_SENT', flags: ['blocklisted_ip', 'odd_port'], age: 47 * MIN }));
      return c;
    }
    function buildPool(P) {
      return [
        [P.edgeNet, '142.250.187.234', 443, 'i.ytimg.com'], [P.edgeNet, '104.16.85.20', 443, 'cdnjs.cloudflare.com'],
        [P.edgeNet, '13.33.88.41', 443, 'd1.awsstatic.com'], [P.edgeNet, '185.199.108.133', 443, 'raw.githubusercontent.com'],
        [P.chromeNet, '142.250.187.206', 443, 'clients4.google.com'], [P.chromeNet, '157.240.227.35', 443, 'static.xx.fbcdn.net'],
        [P.slackNet, '52.29.238.212', 443, 'wss-backup.slack.com'], [P.spotify, '35.186.224.47', 443, 'gew4-spclient.spotify.com'],
        [P.code, '13.107.6.158', 443, 'vscode-sync.trafficmanager.net'], [P.svc.Dnscache, LAN_GW, 53, null, 'UDP'],
      ];
    }
    function buildListening(P) {
      const L = mkListen;
      const sys = { pid: 4, name: 'System', exe: '', trust: 'trusted' };
      return [
        L(P.svc.RpcEptMapper, 'TCP', '0.0.0.0', 135), L(sys, 'TCP', '0.0.0.0', 445), L(P.svc.CDPSvc, 'TCP', '0.0.0.0', 5040),
        L(P.svc.DoSvc, 'TCP', '0.0.0.0', 7680), L(P.lsass, 'TCP', '0.0.0.0', 49664), L(P.svc.EventLog, 'TCP', '0.0.0.0', 49666),
        L(P.svc.Schedule, 'TCP', '0.0.0.0', 49667), L(P.sshd, 'TCP', '0.0.0.0', 22, BOOT - 25),
        L(P.dev, 'TCP', '0.0.0.0', 3000, 2 * HOUR + 44 * MIN), L(P.spotify, 'UDP', '0.0.0.0', 57621, 2 * HOUR + 6 * MIN),
        L(P.steam, 'TCP', '0.0.0.0', 27036, BOOT - 80),
        L(P.tailscaled, 'UDP', '0.0.0.0', 41641), L(P.edge, 'UDP', '0.0.0.0', 5353, 5 * HOUR), L(P.svc.Dnscache, 'UDP', '0.0.0.0', 5355),
        L(sys, 'TCP', LAN_IP, 139), L(P.tailscaled, 'TCP', TS_IP, 61473),
        L(P.engine, 'TCP', '127.0.0.1', 8777, ENGINE_UP), L(P.httpd, 'TCP', '127.0.0.1', 8790, 41 * MIN),
        L(P.spotify, 'TCP', '127.0.0.1', 4381, 2 * HOUR + 6 * MIN), L(P.steam, 'TCP', '127.0.0.1', 27060, BOOT - 80),
      ];
    }

    function buildAlerts(P) {
      const mal = ref('updsvc.exe', MAL_PID);
      const list = [
        A(46, 'critical', 'network', `Connection to blocklisted IP ${C2}:${C2_PORT}`,
          'updsvc.exe (HashMismatch signature) tried to reach a known malware server.',
          { first: 47 * MIN, last: 70, count: 14, process: mal, remote: { ip: C2, port: C2_PORT, host: null },
            details: { rule: 'blocklisted_ip', state: 'SYN_SENT', direction: 'out', blocklist_note: 'example C2 (demo data)', flags: ['blocklisted_ip', 'odd_port', 'sig_mismatch'] } }),
        A(47, 'high', 'persistence', 'New Run key: UpdSvc',
          'A new autostart entry launches updsvc.exe from C:\\ProgramData at every logon.',
          { last: 46 * MIN, process: mal,
            details: { rule: 'new_persistence', kind: 'run_key', location: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', name: 'UpdSvc', command: `"${UPDSVC}" /auto`, flags: ['user_writable_path', 'sig_mismatch'] } }),
        A(45, 'medium', 'process', 'Padded executable: updsvc.exe (612 MB, 97% zero bytes)',
          'Malware often pads files past antivirus upload limits. The signature no longer matches the file.',
          { last: 47 * MIN, process: mal, details: { rule: 'padded_binary', size_mb: 612, zero_ratio: 0.97, flags: ['padded_binary', 'sig_mismatch'] } }),
        A(44, 'medium', 'process', 'LOLBin network activity: powershell.exe → aka.ms',
          'powershell.exe started with -ExecutionPolicy Bypass and downloaded from aka.ms:443.',
          { last: 25 * MIN, process: ref('powershell.exe', P.ps.pid), remote: { ip: '23.53.33.84', port: 443, host: 'aka.ms' },
            details: { rule: 'lolbin_network', parent: 'pwsh.exe', cmdline: P.ps.cmdline, flags: ['lolbin'] } }),
        A(43, 'high', 'privacy', 'Webcam used by camhelper.exe from a hidden folder',
          'Windows recorded camhelper.exe (C:\\Users\\alex\\.cache\\.sys\\…) using the webcam for 22 s, 19 days ago. The file is gone now.',
          { last: ENGINE_UP - 50, process: { pid: null, name: 'camhelper.exe', exe: CAMHELPER, signer: null, sig_status: 'Unknown', trust: 'malicious' },
            details: { rule: 'privacy_hidden_dir', device: 'webcam', start: ago(CAM_AGO), stop: ago(CAM_AGO - 22), source: 'CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged', file_exists: false, flags: ['hidden_dir', 'user_writable_path'] } }),
        A(42, 'high', 'defender', 'Microsoft Defender detected Trojan:Win32/Wacatac.B!ml',
          'Quarantined C:\\Users\\alex\\Downloads\\free-game-cheats.zip->setup.exe.',
          { last: 2 * HOUR + 51 * MIN,
            details: { threat: 'Trojan:Win32/Wacatac.B!ml', action: 'Quarantine', event_id: 1117, path: 'C:\\Users\\alex\\Downloads\\free-game-cheats.zip->setup.exe', detection_source: 'Real-time protection', user: `${HOST}\\${USER}` } }),
        A(41, 'medium', 'network', `Inbound SSH connection to sshd.exe:22 from ${PEER}`,
          `A device on your Tailscale network (${PEER_HOST}) connected to the OpenSSH server.`,
          { first: 26 * HOUR, last: 24 * MIN, count: 2, status: 'allowed', process: ref('sshd.exe', P.sshSess.pid), remote: { ip: PEER, port: 52731, host: PEER_HOST },
            details: { rule: 'inbound_connection', local: `${TS_IP}:22` } }),
        A(40, 'medium', 'network', 'Server listening on all interfaces: node.exe:3000',
          'A development server (next dev -H 0.0.0.0) accepts connections on TCP 3000 from any network.',
          { last: 2 * HOUR + 44 * MIN, process: ref('node.exe', P.dev.pid), details: { rule: 'exposed_listener', ports: '3000/tcp', flags: ['exposed'] } }),
        A(39, 'low', 'network', 'OpenSSH server listening on all interfaces: sshd.exe',
          'sshd.exe accepts connections on TCP 22 from any network. Expected if you use SSH; limit it to your tailnet otherwise.',
          { last: ENGINE_UP - 40, process: ref('sshd.exe', P.sshd.pid), details: { rule: 'exposed_listener', ports: '22/tcp', flags: ['exposed'] } }),
        A(38, 'medium', 'process', 'Unsigned app went online: yt-dlp.exe',
          'yt-dlp.exe has no Authenticode signature, runs from your user folder and holds 2 connections.',
          { first: 26 * HOUR, last: 2 * HOUR + 5 * MIN, count: 3, process: ref('yt-dlp.exe', P.ytdlp.pid), details: { rule: 'unsigned_network', flags: ['unsigned', 'user_writable_path'] } }),
        A(36, 'low', 'process', 'First-seen process: winget.exe', 'winget.exe started by powershell.exe (signed by Microsoft Corporation).',
          { last: 24 * MIN, process: ref('winget.exe'), details: { rule: 'first_seen', parent: 'powershell.exe', flags: ['first_seen'] } }),
        A(35, 'low', 'network', 'New destination for node.exe: registry.npmjs.org', 'node.exe connected to 104.16.30.34:443 for the first time.',
          { last: 65 * MIN, process: ref('node.exe', P.npm.pid), remote: { ip: '104.16.30.34', port: 443, host: 'registry.npmjs.org' }, details: { rule: 'new_destination' } }),
        A(34, 'low', 'privacy', 'Microphone in use: Zoom.exe', 'Zoom started using the microphone.',
          { last: 34 * MIN, status: 'allowed', process: ref('Zoom.exe', P.zoom.pid), details: { rule: 'device_in_use', device: 'microphone' } }),
        A(33, 'low', 'network', 'New listening port: python.exe 127.0.0.1:8790', 'Bound to loopback only, so it is not reachable from other machines.',
          { last: 41 * MIN, process: ref('python.exe', P.httpd.pid), details: { rule: 'new_listener', laddr: '127.0.0.1', lport: 8790 } }),
        A(32, 'low', 'process', 'First-seen process: steamwebhelper.exe', 'Steam updated its web helper (signed by Valve Corp.).',
          { last: 90 * MIN, process: ref('steamwebhelper.exe'), details: { rule: 'first_seen', flags: ['first_seen'] } }),
        A(31, 'low', 'network', 'New app online: Code.exe', 'Code.exe opened its first connection (marketplace.visualstudio.com).',
          { first: 9 * DAY, last: 9 * DAY, status: 'acknowledged', process: ref('Code.exe', P.code.pid), remote: { ip: '13.107.42.18', port: 443, host: 'marketplace.visualstudio.com' }, details: { rule: 'new_app_online', flags: ['new_app'] } }),
        A(30, 'low', 'network', 'New destination: Code.exe → api.github.com:443', 'Visual Studio Code connected to a new server.',
          { last: 110 * MIN, process: ref('Code.exe', P.code.pid), remote: { ip: '140.82.112.21', port: 443, host: 'api.github.com' }, details: { rule: 'new_destination' } }),
        A(29, 'low', 'network', 'New destination: Telegram.exe → 149.154.175.53:443', 'Telegram connected to another data centre.',
          { last: 2 * HOUR, process: ref('Telegram.exe', P.telegram.pid), remote: { ip: '149.154.175.53', port: 443, host: null }, details: { rule: 'new_destination' } }),
        A(28, 'low', 'network', `Unusual port: steam.exe → ${LAN_PEER}:27036`, 'Steam Remote Play to another PC on your LAN.',
          { first: 2 * DAY, last: 3 * HOUR, count: 6, process: ref('steam.exe', P.steam.pid), remote: { ip: LAN_PEER, port: 27036, host: null }, details: { rule: 'odd_port', flags: ['odd_port'] } }),
        A(27, 'low', 'network', 'New app online: Zoom.exe', 'Zoom.exe connected to zoom.us for the first time.',
          { first: 6 * DAY, last: 6 * DAY, status: 'acknowledged', process: ref('Zoom.exe', P.zoom.pid), remote: { ip: '170.114.52.2', port: 443, host: 'zoom.us' }, details: { rule: 'new_app_online', flags: ['new_app'] } }),
      ];
      if (FILE_AUDIT) {
        list.push(A(48, 'high', 'file', 'Canary file read: wallet-seed-backup.txt',
          'updsvc.exe opened a decoy file that no legitimate program should touch.',
          { last: 38 * MIN, process: mal, details: { rule: 'canary_access', path: `${HOME}Documents\\Finance\\wallet-seed-backup.txt`, access: 'ReadData', event_id: 4663 } }));
      }
      if (!FULL) {
        list.push(A(25, 'low', 'system', 'DNS query log is off', 'Per-app DNS lookups need admin mode (see README › Admin mode).',
          { last: ENGINE_UP - 5, details: { rule: 'coverage_gap', monitor: 'dns_log' } }));
        list.push(A(24, 'low', 'system', 'Security event log not readable', 'Logon and account events need the engine to run with admin rights (see README › Admin mode).',
          { last: ENGINE_UP - 5, details: { rule: 'coverage_gap', monitor: 'security_log' } }));
      }
      return list;
    }

    function infoEvents(E) {
      E(BOOT, 'info', 'system', 'Windows started', 'Fast startup disabled; full boot.');
      E(BOOT - 90, 'info', 'account', `${USER} signed in`, 'Interactive logon (Windows Hello PIN).');
      E(BOOT - 20, 'info', 'network', 'Tailscale connected', `This PC is ${TS_IP} on the tailnet.`);
      E(3 * HOUR, 'info', 'defender', 'Defender signatures updated', 'Security intelligence 1.463.9.0.');
      E(27 * HOUR, 'info', 'defender', 'Defender quick scan finished', 'No threats found.');
      E(26 * HOUR + 12 * MIN, 'info', 'system', 'System resumed from sleep', '');
      E(26 * HOUR + 11 * MIN, 'info', 'account', 'Workstation unlocked', USER);
      E(6 * HOUR + 2 * MIN, 'info', 'account', 'Workstation unlocked', USER);
      E(34 * MIN, 'info', 'privacy', 'Microphone in use: Zoom.exe', 'Video call.');
      E(21 * HOUR + 4 * MIN, 'info', 'privacy', 'Camera in use: Telegram.exe', 'Video call.');
      E(20 * HOUR + 46 * MIN, 'info', 'privacy', 'Camera released: Telegram.exe', 'In use for 18m 12s.');
      E(25 * HOUR, 'info', 'persistence', 'Scheduled task changed: GoogleUpdaterTaskUser141.0.7390.55', 'Command now points at updater.exe 141.0.7390.55.');
      E(2 * DAY + 1 * HOUR, 'info', 'persistence', 'Autostart baseline refreshed', '21 entries across Run keys, Startup folder, scheduled tasks and services.');
      E(2 * MIN, 'info', 'file', 'Edge saved passwords read by msedge.exe', 'Expected reader.');
      E(41 * MIN, 'info', 'network', 'Listening: python.exe 127.0.0.1:8790', 'Loopback only.');
    }

    function buildPrivacy() {
      return {
        devices: {
          webcam: { in_use: false, by: [] },
          microphone: { in_use: true, by: ['Zoom.exe'] },
          location: { in_use: false, by: [] },
          screen_capture: { in_use: false, by: [] },
        },
        history: [
          { device: 'microphone', app: 'Zoom.exe', path: ZOOM, start: ago(34 * MIN), stop: null, in_use: true, trust: 'trusted', allowed: true },
          { device: 'webcam', app: 'Zoom.exe', path: ZOOM, start: ago(5 * HOUR + 2 * MIN), stop: ago(4 * HOUR + 31 * MIN), in_use: false, trust: 'trusted', allowed: true },
          { device: 'webcam', app: 'Telegram.exe', path: TELEGRAM, start: ago(21 * HOUR + 4 * MIN), stop: ago(20 * HOUR + 46 * MIN), in_use: false, trust: 'trusted', allowed: true },
          { device: 'microphone', app: 'Telegram.exe', path: TELEGRAM, start: ago(21 * HOUR + 4 * MIN), stop: ago(20 * HOUR + 46 * MIN), in_use: false, trust: 'trusted', allowed: true },
          { device: 'screen_capture', app: 'slack.exe', path: SLACK, start: ago(26 * HOUR + 30 * MIN), stop: ago(26 * HOUR + 8 * MIN), in_use: false, trust: 'trusted', allowed: false },
          { device: 'microphone', app: 'chrome.exe', path: CHROME, start: ago(2 * DAY + 7 * HOUR), stop: ago(2 * DAY + 7 * HOUR - 372), in_use: false, trust: 'trusted', allowed: false },
          { device: 'location', app: 'msedge.exe', path: EDGE, start: ago(3 * DAY + 2 * HOUR), stop: ago(3 * DAY + 2 * HOUR - 2), in_use: false, trust: 'trusted', allowed: true },
          { device: 'webcam', app: 'WindowsCamera.exe', path: 'Microsoft.WindowsCamera_8wekyb3d8bbwe', start: ago(6 * DAY + 4 * HOUR), stop: ago(6 * DAY + 4 * HOUR - 71), in_use: false, trust: 'known', allowed: false },
          { device: 'webcam', app: 'camhelper.exe', path: CAMHELPER, start: ago(CAM_AGO), stop: ago(CAM_AGO - 22), in_use: false, trust: 'unknown (file gone)', allowed: false },
        ],
      };
    }

    function buildPersistence() {
      const RUN = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
      const RUNM = 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
      const STARTUP = `${HOME}AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup`;
      const it = mkPersist;
      const ex = (n) => img[n][0];
      const GUPD = `${HOME}AppData\\Local\\Google\\GoogleUpdater\\141.0.7390.55\\updater.exe`;
      const EUPD = 'C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe';
      const SENTINEL = `${HOME}AppData\\Local\\Programs\\PC Sentinel\\PC Sentinel.exe`;
      return [
        it('run_key', RUN, 'UpdSvc', `"${UPDSVC}" /auto`, UPDSVC, 'Contoso Software Ltd.', 'HashMismatch', 'malicious', 'new', 46 * MIN, ['user_writable_path', 'sig_mismatch', 'padded_binary']),
        it('run_key', RUN, 'Telegram Desktop', `"${TELEGRAM}" -autostart`, TELEGRAM, 'Telegram FZ-LLC', 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('run_key', RUN, 'MicrosoftEdgeAutoLaunch_0D3C7A51B2E94F6A8C1D', `"${EDGE}" --no-startup-window --win-session-start`, EDGE, MSC, 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('run_key', RUN, 'Spotify', `"${SPOTIFY}" --autostart --minimized`, SPOTIFY, 'Spotify AB', 'Valid', 'trusted', 'baseline', 30 * DAY),
        it('run_key', RUN, 'com.squirrel.slack.slack', `"${win('C:/Users/alex/AppData/Local/slack/slack.exe')}" --process-start-args --startup`, win('C:/Users/alex/AppData/Local/slack/slack.exe'), 'Slack Technologies, LLC', 'Valid', 'trusted', 'baseline', 30 * DAY),
        it('run_key', RUN, 'Steam', `"${STEAM}" -silent`, STEAM, 'Valve Corp.', 'Valid', 'trusted', 'baseline', 35 * DAY),
        it('run_key', RUNM, 'SecurityHealth', '%windir%\\system32\\SecurityHealthSystray.exe', ex('SecurityHealthSystray.exe'), MSW, 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('run_key', RUNM, 'Tailscale', `"${ex('tailscale-ipn.exe')}"`, ex('tailscale-ipn.exe'), 'Tailscale Inc.', 'Valid', 'trusted', 'baseline', 22 * DAY),
        it('run_key', RUNM, 'RtkAudUService', `"${ex('RtkAudUService64.exe')}" -background`, ex('RtkAudUService64.exe'), 'Realtek Semiconductor Corp.', 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('startup_folder', STARTUP, 'PC Sentinel.lnk', `"${SENTINEL}" --tray`, SENTINEL, null, 'NotSigned', 'known', 'baseline', 2 * DAY),
        it('scheduled_task', '\\', 'GoogleUpdaterTaskUser141.0.7390.55{6B1E0F2A-3C4D-4E5F-8A9B-0C1D2E3F4A5B}', `"${GUPD}" --wake`, GUPD, 'Google LLC', 'Valid', 'trusted', 'changed', 25 * HOUR),
        it('scheduled_task', '\\', 'MicrosoftEdgeUpdateTaskMachineCore{5E9A1C3B-7D2F-4A6E-B0C8-1F3D5B7A9E2C}', `"${EUPD}" /c`, EUPD, MSC, 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('scheduled_task', '\\', 'MicrosoftEdgeUpdateTaskMachineUA{9C7B5A3E-1D2F-4B6A-8E0C-2A4C6E8B0D1F}', `"${EUPD}" /ua /installsource scheduler`, EUPD, MSC, 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('scheduled_task', '\\', 'OneDrive Reporting Task-S-1-5-21-1111111111-2222222222-3333333333-1001', '%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe /reporting', `${HOME}AppData\\Local\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe`, null, 'Unknown', 'known', 'removed', 30 * DAY, ['missing_file']),
        it('service', 'Service (Automatic)', 'sshd', `"${SSHD}"`, SSHD, MSW, 'Valid', 'trusted', 'baseline', 22 * DAY),
        it('service', 'Service (Automatic)', 'Tailscale', `"${ex('tailscaled.exe')}"`, ex('tailscaled.exe'), 'Tailscale Inc.', 'Valid', 'trusted', 'baseline', 22 * DAY),
        it('service', 'Service (Automatic)', 'WinDefend', `"${ex('MsMpEng.exe')}"`, ex('MsMpEng.exe'), MSC, 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('service', 'Service (Manual)', 'edgeupdate', `"${EUPD}" /svc`, EUPD, MSC, 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('service', 'Service (Manual)', 'Steam Client Service', '"C:\\Program Files (x86)\\Common Files\\Steam\\steamservice.exe" /RunAsService', 'C:\\Program Files (x86)\\Common Files\\Steam\\steamservice.exe', 'Valve Corp.', 'Valid', 'trusted', 'baseline', 35 * DAY),
      ];
    }

    function buildFiles(P) {
      const L = `${HOME}AppData\\Local\\`;
      const R = `${HOME}AppData\\Roaming\\`;
      const W = (path, label, kind, exists) => ({ path, label, kind, audited: FILE_AUDIT, exists: exists !== false });
      const watched = [
        W(`${L}Microsoft\\Edge\\User Data\\Default\\Login Data`, 'Edge saved passwords', 'credential'),
        W(`${L}Microsoft\\Edge\\User Data\\Default\\Network\\Cookies`, 'Edge cookies', 'credential'),
        W(`${L}Google\\Chrome\\User Data\\Default\\Login Data`, 'Chrome saved passwords', 'credential'),
        W(`${L}Google\\Chrome\\User Data\\Default\\Network\\Cookies`, 'Chrome cookies', 'credential'),
        W(`${R}Mozilla\\Firefox\\Profiles\\k3j2h1g0.default-release\\logins.json`, 'Firefox saved passwords', 'credential', false),
        W(`${HOME}.git-credentials`, 'Git credentials', 'credential'),
        W(`${R}GitHub CLI\\hosts.yml`, 'GitHub CLI token', 'credential'),
        W(`${HOME}.ssh\\id_ed25519`, 'SSH private key', 'ssh'),
        W(`${HOME}.ssh\\known_hosts`, 'SSH known hosts', 'ssh'),
        W(`${L}Microsoft\\Edge\\User Data\\Default\\Local Extension Settings\\ejbalbakoplchlghecdalmeeeajnimhm`, 'MetaMask vault (Edge)', 'wallet', false),
        W(`${R}Exodus\\exodus.wallet`, 'Exodus wallet', 'wallet', false),
        W(`${R}Electrum\\wallets`, 'Electrum wallets', 'wallet', false),
        W(`${R}Telegram Desktop\\tdata`, 'Telegram session (tdata)', 'messenger'),
        W(`${L}Packages\\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\\LocalState`, 'WhatsApp Desktop', 'messenger'),
        W(`${HOME}Documents\\Finance\\wallet-seed-backup.txt`, 'Canary: wallet seed backup', 'canary', FILE_AUDIT),
        W(`${HOME}Desktop\\passwords-old.xlsx`, 'Canary: passwords spreadsheet', 'canary', FILE_AUDIT),
        W(`${HOME}.aws\\credentials`, 'Canary: AWS credentials', 'canary', FILE_AUDIT),
      ];
      const X = (sec, w, kind, proc, pid, exe, access, expected) => ({ ts: ago(sec), path: w.path, label: w.label, kind, process: proc, pid, exe, access, expected });
      const access = !FILE_AUDIT ? [] : [
        X(2 * MIN, watched[0], 'credential', 'msedge.exe', P.edge.pid, EDGE, 'ReadData', true),
        X(5 * MIN, watched[12], 'messenger', 'Telegram.exe', P.telegram.pid, TELEGRAM, 'WriteData', true),
        X(38 * MIN, watched[14], 'canary', 'updsvc.exe', MAL_PID, UPDSVC, 'ReadData', false),
        X(62 * MIN, watched[7], 'ssh', 'ssh.exe', 11204, 'C:\\Windows\\System32\\OpenSSH\\ssh.exe', 'ReadData', true),
        X(2 * HOUR + 10 * MIN, watched[5], 'credential', 'git-credential-manager.exe', 9936, 'C:\\Program Files\\Git\\mingw64\\bin\\git-credential-manager.exe', 'ReadData', true),
        X(3 * HOUR, watched[6], 'credential', 'gh.exe', 14472, 'C:\\Program Files\\GitHub CLI\\gh.exe', 'ReadData', true),
        X(7 * HOUR + 30 * MIN, watched[2], 'credential', 'chrome.exe', P.chrome.pid, CHROME, 'ReadData', true),
        X(9 * HOUR, watched[1], 'credential', 'MsMpEng.exe', P.defender.pid, img['MsMpEng.exe'][0], 'ReadData', true),
      ];
      return { watched, access };
    }

    return {
      platform: 'windows', os: 'Windows 11 (26200)', osWord: 'Windows', img,
      protectedNames: ['System', 'Registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'winlogon.exe', 'svchost.exe', 'dwm.exe', 'fontdrvhost.exe'],
      supported: { processes: true, network: true, privacy: true, persistence: true, defender_log: true, security_log: true, dns_log: true, file_audit: true, canaries: true },
      coverage: () => ({ processes: true, network: true, privacy: true, persistence: true, defender_log: true, security_log: FULL, dns_log: FULL, file_audit: FILE_AUDIT, canaries: FILE_AUDIT ? 3 : 0 }),
      defender: () => ({ realtime: true, tamper: true, signatures: '1.463.9.0', signatures_age_h: 3, exclusions_known: 0, last_detection: ago(2 * HOUR + 51 * MIN) }),
      autostart: { supported: true, enabled: true, detail: 'Startup folder shortcut' },
      blockMessage: (ip) => `Firewall rule for ${ip}: requested. Approve the Windows admin prompt to apply it.`,
      buildProcesses, buildConnections, buildPool, buildListening, buildAlerts, infoEvents, buildPrivacy, buildPersistence, buildFiles,
      isAppStart: (p) => p.ppid === 5212 || ['python.exe', 'node.exe', 'pwsh.exe', 'powershell.exe', 'winget.exe', 'WindowsTerminal.exe', 'yt-dlp.exe'].includes(p.name),
      eventApps: ['msedge.exe', 'chrome.exe', 'Telegram.exe', 'node.exe', 'python.exe', 'slack.exe', 'Spotify.exe', 'Code.exe', 'git.exe', 'ssh.exe', 'steam.exe', 'Zoom.exe'],
      eventHosts: [['github.com', '140.82.113.3', 443], ['pypi.org', '151.101.0.223', 443], ['api.github.com', '140.82.112.21', 443], ['zoom.us', '170.114.52.2', 443],
        ['app.slack.com', '18.66.218.31', 443], ['149.154.167.51', '149.154.167.51', 443], ['www.youtube.com', '142.250.181.238', 443], ['registry.npmjs.org', '104.16.30.34', 443]],
      destExtra: [
        ['185.199.110.133', 'objects.githubusercontent.com', 443, 'node.exe'], ['13.69.109.130', 'settings-win.data.microsoft.com', 443, 'svchost.exe'],
        ['52.182.143.212', 'v10.events.data.microsoft.com', 443, 'svchost.exe'], ['104.244.42.193', 'api.x.com', 443, 'chrome.exe'],
        ['31.13.72.36', 'www.facebook.com', 443, 'chrome.exe'], ['91.108.56.130', null, 443, 'Telegram.exe'], [LAN_GW, null, 53, 'svchost.exe'],
        ['23.40.230.17', 'download.windowsupdate.com', 80, 'svchost.exe'], ['8.8.8.8', 'dns.google', 443, 'msedge.exe'],
      ],
      allowlist: [
        { id: 6, kind: 'process', value: VENV_PY, note: 'PC Sentinel engine', ts: ago(2 * DAY) },
        { id: 5, kind: 'persistence', value: SSHD, note: 'OpenSSH server for my laptop', ts: ago(5 * DAY) },
        { id: 4, kind: 'privacy', value: ZOOM, note: 'video calls', ts: ago(5 * DAY) },
        { id: 3, kind: 'privacy', value: EDGE, note: 'Meet / Teams calls', ts: ago(6 * DAY) },
        { id: 2, kind: 'destination', value: PEER, note: 'my laptop over Tailscale (SSH)', ts: ago(6 * DAY) },
        { id: 1, kind: 'process', value: NODE, note: 'dev tool', ts: ago(9 * DAY) },
      ],
      dns: [['msedge.exe', 'meet.google.com', 'A', '142.250.185.78'], ['chrome.exe', 'www.google.com', 'A', '142.250.181.206'], ['slack.exe', 'wss-primary.slack.com', 'A', '52.29.238.212'],
        ['Code.exe', 'marketplace.visualstudio.com', 'A', '13.107.42.18'], ['updsvc.exe', 'update-check.example.net', 'A', C2], ['node.exe', 'registry.npmjs.org', 'AAAA', '2606:4700::6810:1e22'],
        ['Telegram.exe', 'telegram.org', 'A', '149.154.167.99'], ['svchost.exe', 'settings-win.data.microsoft.com', 'A', '13.69.109.130']],
      streamPool: (P) => [
        () => ({ severity: 'low', category: 'network', title: 'New destination: msedge.exe → i.ytimg.com', summary: 'First connection from Edge to 142.250.187.234:443.', process: ref('msedge.exe', P.edgeNet.pid), remote: { ip: '142.250.187.234', port: 443, host: 'i.ytimg.com' }, details: { rule: 'new_destination' } }),
        () => ({ severity: 'medium', category: 'network', title: 'New exposed listener: python.exe 0.0.0.0:8000', summary: 'A quick file server (python -m http.server) is reachable from your LAN and tailnet.', process: ref('python.exe', P.pip.pid, SYS_PY), details: { rule: 'exposed_listener', ports: '8000/tcp', flags: ['exposed'] } }),
        () => ({ severity: 'low', category: 'process', title: 'First-seen process: git-remote-https.exe', summary: 'Started by git.exe (signed by Johannes Schindelin).', process: { pid: rint(400, 9000) * 4, name: 'git-remote-https.exe', exe: 'C:\\Program Files\\Git\\mingw64\\libexec\\git-core\\git-remote-https.exe', signer: 'Johannes Schindelin', sig_status: 'Valid', trust: 'known' }, details: { rule: 'first_seen', flags: ['first_seen'] } }),
        () => (!FILE_AUDIT ? null : { severity: 'high', category: 'file', title: 'Edge saved passwords read by updsvc.exe', summary: 'An untrusted program opened the browser password database.', process: ref('updsvc.exe', MAL_PID), details: { rule: 'credential_access', path: db.files.watched[0].path, access: 'ReadData', event_id: 4663 } }),
        () => ({ severity: 'low', category: 'network', title: 'New destination: python.exe → download.pytorch.org', summary: 'pip connected to 18.239.94.112:443.', process: ref('python.exe', P.pip.pid, SYS_PY), remote: { ip: '18.239.94.112', port: 443, host: 'download.pytorch.org' }, details: { rule: 'new_destination' } }),
      ],
    };
  }

  /* ================================================================== profile: macOS */
  function macProfile() {
    const APPLE = 'Apple Inc.';
    const HOME = '/Users/alex/';
    const WK = '/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/';
    const CHROME_FW = '/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/141.0.7390.55/Helpers/';
    const UPDSVC = `${HOME}Library/Application Support/.updsvc/updsvc`;
    const CAMHELPER = `${HOME}.cache/.sys/camhelper`;
    const NODE = '/opt/homebrew/bin/node';
    const PY = '/opt/homebrew/bin/python3';
    const ZOOM = '/Applications/zoom.us.app/Contents/MacOS/zoom.us';
    const img = {
      'kernel_task': ['', APPLE, 'Valid', 'trusted'],
      'launchd': ['/sbin/launchd', APPLE, 'Valid', 'trusted'],
      'logd': ['/usr/libexec/logd', APPLE, 'Valid', 'trusted'],
      'UserEventAgent': ['/usr/libexec/UserEventAgent', APPLE, 'Valid', 'trusted'],
      'configd': ['/usr/libexec/configd', APPLE, 'Valid', 'trusted'],
      'powerd': ['/System/Library/CoreServices/powerd.bundle/powerd', APPLE, 'Valid', 'trusted'],
      'notifyd': ['/usr/sbin/notifyd', APPLE, 'Valid', 'trusted'],
      'mds': ['/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds', APPLE, 'Valid', 'trusted'],
      'mds_stores': ['/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds_stores', APPLE, 'Valid', 'trusted'],
      'WindowServer': ['/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer', APPLE, 'Valid', 'trusted'],
      'loginwindow': ['/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow', APPLE, 'Valid', 'trusted'],
      'mDNSResponder': ['/usr/sbin/mDNSResponder', APPLE, 'Valid', 'trusted'],
      'trustd': ['/usr/libexec/trustd', APPLE, 'Valid', 'trusted'],
      'apsd': ['/System/Library/PrivateFrameworks/ApplePushService.framework/apsd', APPLE, 'Valid', 'trusted'],
      'nsurlsessiond': ['/usr/libexec/nsurlsessiond', APPLE, 'Valid', 'trusted'],
      'cloudd': ['/System/Library/PrivateFrameworks/CloudKitDaemon.framework/Support/cloudd', APPLE, 'Valid', 'trusted'],
      'rapportd': ['/usr/libexec/rapportd', APPLE, 'Valid', 'trusted'],
      'sharingd': ['/usr/libexec/sharingd', APPLE, 'Valid', 'trusted'],
      'ControlCenter': ['/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter', APPLE, 'Valid', 'trusted'],
      'Finder': ['/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder', APPLE, 'Valid', 'trusted'],
      'Dock': ['/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock', APPLE, 'Valid', 'trusted'],
      'SystemUIServer': ['/System/Library/CoreServices/SystemUIServer.app/Contents/MacOS/SystemUIServer', APPLE, 'Valid', 'trusted'],
      'Spotlight': ['/System/Library/CoreServices/Spotlight.app/Contents/MacOS/Spotlight', APPLE, 'Valid', 'trusted'],
      'coreaudiod': ['/usr/sbin/coreaudiod', APPLE, 'Valid', 'trusted'],
      'bluetoothd': ['/usr/sbin/bluetoothd', APPLE, 'Valid', 'trusted'],
      'syspolicyd': ['/usr/libexec/syspolicyd', APPLE, 'Valid', 'trusted'],
      'softwareupdated': ['/System/Library/PrivateFrameworks/SoftwareUpdate.framework/Resources/softwareupdated', APPLE, 'Valid', 'trusted'],
      'Safari': ['/Applications/Safari.app/Contents/MacOS/Safari', APPLE, 'Valid', 'trusted'],
      'com.apple.WebKit.Networking': [`${WK}com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking`, APPLE, 'Valid', 'trusted'],
      'com.apple.WebKit.WebContent': [`${WK}com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent`, APPLE, 'Valid', 'trusted'],
      'Google Chrome': ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', 'Google LLC', 'Valid', 'trusted'],
      'Google Chrome Helper': [`${CHROME_FW}Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper`, 'Google LLC', 'Valid', 'trusted'],
      'Google Chrome Helper (Renderer)': [`${CHROME_FW}Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)`, 'Google LLC', 'Valid', 'trusted'],
      'Slack': ['/Applications/Slack.app/Contents/MacOS/Slack', 'Slack Technologies, Inc.', 'Valid', 'trusted'],
      'Slack Helper': ['/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper', 'Slack Technologies, Inc.', 'Valid', 'trusted'],
      'zoom.us': [ZOOM, 'Zoom Video Communications, Inc.', 'Valid', 'trusted'],
      'Telegram': ['/Applications/Telegram.app/Contents/MacOS/Telegram', 'Telegram FZ-LLC', 'Valid', 'trusted'],
      'Spotify': ['/Applications/Spotify.app/Contents/MacOS/Spotify', 'Spotify AB', 'Valid', 'trusted'],
      'Code': ['/Applications/Visual Studio Code.app/Contents/MacOS/Code', 'Microsoft Corporation', 'Valid', 'trusted'],
      'Code Helper': ['/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper', 'Microsoft Corporation', 'Valid', 'trusted'],
      'steam_osx': [`${HOME}Library/Application Support/Steam/Steam.AppBundle/Steam/Contents/MacOS/steam_osx`, 'Valve Corporation', 'Valid', 'trusted'],
      'Tailscale': ['/Applications/Tailscale.app/Contents/MacOS/Tailscale', 'Tailscale Inc.', 'Valid', 'trusted'],
      'Terminal': ['/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal', APPLE, 'Valid', 'trusted'],
      'login': ['/usr/bin/login', APPLE, 'Valid', 'trusted'],
      'zsh': ['/bin/zsh', APPLE, 'Valid', 'trusted'],
      'sh': ['/bin/sh', APPLE, 'Valid', 'trusted'],
      'curl': ['/usr/bin/curl', APPLE, 'Valid', 'trusted'],
      'sshd-session': ['/usr/libexec/sshd-session', APPLE, 'Valid', 'trusted'],
      'node': [NODE, null, 'NotSigned', 'known'],
      'python3': [PY, null, 'NotSigned', 'known'],
      'yt-dlp_macos': [`${HOME}bin/yt-dlp_macos`, null, 'NotSigned', 'unsigned'],
      'updsvc': [UPDSVC, 'Contoso Software Ltd.', 'HashMismatch', 'malicious'],
      'camhelper': [CAMHELPER, null, 'NotSigned', 'suspicious'],
    };

    function buildProcesses() {
      const { procs, add, child } = treeBuilder({ reserved: [0, 1, MAL_PID], pid: () => rint(300, 99000) });
      const P = {};
      add('kernel_task', { pid: 0, user: 'root', age: BOOT, mem: 1800, cmd: '', cpu: 2.1 });
      const launchd = P.launchd = add('launchd', { pid: 1, user: 'root', age: BOOT, mem: 14, cmd: '/sbin/launchd', cpu: 0.3 });
      const sysd = (name, user, o) => child(launchd, name, Object.assign({ user, age: rint(BOOT - 60, BOOT - 2) }, o || {}));
      ['logd', 'UserEventAgent', 'configd', 'powerd', 'notifyd', 'mds', 'syspolicyd', 'bluetoothd', 'softwareupdated'].forEach((n) => sysd(n, 'root', { mem: rint(4, 40) }));
      sysd('mds_stores', 'root', { mem: 88, cpu: 0.4 });
      sysd('WindowServer', '_windowserver', { mem: 420, cpu: 3.4, cmd: '/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer -daemon' });
      sysd('coreaudiod', '_coreaudiod', { mem: 22, cpu: 0.8 });
      P.mdns = sysd('mDNSResponder', '_mdnsresponder', { mem: 9, cpu: 0.1 });
      P.trustd = sysd('trustd', 'root', { mem: 12 });
      P.apsd = sysd('apsd', 'root', { mem: 10 });
      P.nsurl = sysd('nsurlsessiond', 'root', { mem: 11 });
      sysd('loginwindow', USER, { age: BOOT - 40, mem: 38 });
      P.cloudd = child(launchd, 'cloudd', { age: BOOT - 35, mem: 26 });
      P.rapportd = child(launchd, 'rapportd', { age: BOOT - 35, mem: 9 });
      child(launchd, 'sharingd', { age: BOOT - 35, mem: 18 });
      P.cc = child(launchd, 'ControlCenter', { age: BOOT - 34, mem: 52, cpu: 0.2 });
      ['Finder', 'Dock', 'SystemUIServer', 'Spotlight'].forEach((n) => child(launchd, n, { age: BOOT - 34, mem: rint(30, 120), cpu: 0.1 }));

      P.safari = child(launchd, 'Safari', { age: 4 * HOUR, mem: 240, cpu: 0.5 });
      P.safariNet = child(launchd, 'com.apple.WebKit.Networking', { age: 4 * HOUR, mem: 34, cpu: 0.3 });
      for (let i = 0; i < 6; i++) child(launchd, 'com.apple.WebKit.WebContent', { age: rint(5 * MIN, 4 * HOUR), mem: rint(60, 380), cpu: i ? 0.1 : 1.8 });
      P.chrome = child(launchd, 'Google Chrome', { age: BOOT - 30, mem: 210, cpu: 0.4 });
      P.chromeNet = child(P.chrome, 'Google Chrome Helper', { age: BOOT - 30, mem: 44, cpu: 0.3, cmd: `"${img['Google Chrome Helper'][0]}" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US` });
      child(P.chrome, 'Google Chrome Helper', { age: BOOT - 30, mem: 160, cpu: 0.9, cmd: `"${img['Google Chrome Helper'][0]}" --type=gpu-process --lang=en-US` });
      for (let i = 0; i < 8; i++) child(P.chrome, 'Google Chrome Helper (Renderer)', { age: rint(5 * MIN, BOOT - 31), mem: rint(40, 300), cmd: `"${img['Google Chrome Helper (Renderer)'][0]}" --type=renderer --renderer-client-id=${8 + i}` });
      P.slack = child(launchd, 'Slack', { age: BOOT - 32, mem: 190, cpu: 0.3 });
      P.slackNet = child(P.slack, 'Slack Helper', { age: BOOT - 32, mem: 40, cpu: 0.2, cmd: `"${img['Slack Helper'][0]}" --type=utility --utility-sub-type=network.mojom.NetworkService` });
      for (let i = 0; i < 2; i++) child(P.slack, 'Slack Helper', { age: BOOT - 32, mem: rint(90, 300), cmd: `"${img['Slack Helper'][0]}" --type=renderer` });
      P.zoom = child(launchd, 'zoom.us', { age: 36 * MIN, mem: 330, cpu: 7.1 });
      P.telegram = child(launchd, 'Telegram', { age: BOOT - 31, mem: 180, cpu: 0.2 });
      P.spotify = child(launchd, 'Spotify', { age: 2 * HOUR + 6 * MIN, mem: 240, cpu: 0.9 });
      P.code = child(launchd, 'Code', { age: 6 * HOUR, mem: 260, cpu: 0.6 });
      for (let i = 0; i < 3; i++) child(P.code, 'Code Helper', { age: 6 * HOUR, mem: rint(80, 480), cpu: i ? 0.2 : 1.2 });
      P.steam = child(launchd, 'steam_osx', { age: BOOT - 29, mem: 150, cpu: 0.3 });
      P.tailscale = child(launchd, 'Tailscale', { age: BOOT - 33, mem: 36, cpu: 0.1 });
      P.sshSess = child(launchd, 'sshd-session', { user: 'root', age: 24 * MIN, mem: 7, cpu: 0.1, cmd: `sshd-session: ${USER} [priv]` });

      const term = child(launchd, 'Terminal', { age: 3 * HOUR + 20 * MIN, mem: 96, cpu: 0.2 });
      const login1 = child(term, 'login', { user: 'root', age: 3 * HOUR + 20 * MIN, mem: 3, cmd: `login -pf ${USER}` });
      const login2 = child(term, 'login', { user: 'root', age: 58 * MIN, mem: 3, cmd: `login -pf ${USER}` });
      const zsh1 = child(login1, 'zsh', { age: 3 * HOUR + 20 * MIN, mem: 6, cmd: '-zsh' });
      const zsh2 = child(login2, 'zsh', { age: 58 * MIN, mem: 6, cmd: '-zsh' });
      P.engine = child(zsh1, 'python3', { age: ENGINE_UP, mem: 72, cpu: 0.9, cmd: `${HOME}src/pc-sentinel/.venv/bin/python3 main.py --port 8777` });
      P.httpd = child(zsh2, 'python3', { age: 41 * MIN, mem: 21, cmd: `python3 -m http.server 8790 --bind 127.0.0.1 --directory ${HOME}src/pc-sentinel/dashboard` });
      P.dev = child(zsh1, 'node', { age: 2 * HOUR + 44 * MIN, mem: 112, cpu: 0.2, cmd: `node ${HOME}src/webapp/node_modules/.bin/next dev -H 0.0.0.0 -p 3000` });
      P.npm = child(zsh1, 'node', { age: 66 * MIN, mem: 88, cpu: 0.1, cmd: '/opt/homebrew/bin/node /opt/homebrew/bin/npm install' });
      P.pip = child(zsh2, 'python3', { age: 53 * MIN, mem: 190, cpu: 0.4, cmd: 'python3 -m pip install --upgrade torch torchvision' });
      P.ytdlp = child(zsh2, 'yt-dlp_macos', { age: 2 * HOUR + 5 * MIN, mem: 58, cpu: 0.6, flags: ['unsigned', 'user_writable_path'], cmd: `${HOME}bin/yt-dlp_macos -x --audio-format mp3 https://www.youtube.com/watch?v=aqz-KE-bpKQ` });
      P.curl = child(zsh2, 'curl', { age: 25 * MIN, mem: 5, flags: ['lolbin'], cmd: 'curl -fsSL https://example.com/install.sh' });
      child(zsh2, 'sh', { age: 25 * MIN, mem: 3, cmd: 'sh' });

      P.mal = child(launchd, 'updsvc', { pid: MAL_PID, age: 47 * MIN, mem: 23, cpu: 0.1, cmd: `"${UPDSVC}" --daemon`, flags: ['sig_mismatch', 'hidden_dir', 'user_writable_path'] });
      P.cam = child(launchd, 'camhelper', { age: 47 * MIN, mem: 9, cmd: CAMHELPER, flags: ['unsigned', 'hidden_dir', 'user_writable_path'] });
      return { procs, P };
    }

    function buildConnections(P) {
      const c = [];
      [
        ['142.250.181.206', 443, 'www.google.com'], ['142.250.181.238', 443, 'www.youtube.com'], ['17.253.144.10', 443, 'www.apple.com'],
        ['140.82.114.26', 443, 'alive.github.com'], ['104.18.32.47', 443, 'github.githubassets.com'], ['151.101.1.140', 443, 'www.reddit.com'],
        ['208.80.154.224', 443, 'en.wikipedia.org'], ['216.58.212.10', 443, 'fonts.googleapis.com'],
      ].forEach(([ip, port, host]) => c.push(mkConn(P.safariNet, ip, port, host)));
      [
        ['172.217.19.110', 443, 'mail.google.com'], ['142.250.186.46', 443, 'docs.google.com'], ['142.250.185.78', 443, 'meet.google.com'],
        ['142.250.187.238', 443, 'accounts.google.com'], ['151.101.193.69', 443, 'stackoverflow.com'],
      ].forEach(([ip, port, host]) => c.push(mkConn(P.chromeNet, ip, port, host)));
      [
        ['52.29.238.212', 443, 'wss-primary.slack.com'], ['18.66.218.31', 443, 'edgeapi.slack.com'], ['35.157.212.10', 443, 'files.slack.com'],
      ].forEach(([ip, port, host]) => c.push(mkConn(P.slackNet, ip, port, host, { age: rint(10 * MIN, BOOT - 40) })));
      c.push(mkConn(P.zoom, '170.114.52.2', 443, 'zoom.us', { age: 36 * MIN }));
      c.push(mkConn(P.zoom, '170.114.10.86', 8801, null, { proto: 'UDP', age: 34 * MIN }));
      c.push(mkConn(P.telegram, '149.154.167.51', 443, null));
      c.push(mkConn(P.telegram, '149.154.175.53', 443, null, { age: 2 * HOUR }));
      c.push(mkConn(P.spotify, '35.186.224.25', 443, 'spclient.wg.spotify.com', { age: 2 * HOUR }));
      c.push(mkConn(P.spotify, '104.199.65.124', 4070, 'ap-gew4.spotify.com', { age: 2 * HOUR }));
      c.push(mkConn(P.code, '13.107.42.18', 443, 'marketplace.visualstudio.com', { age: 6 * HOUR }));
      c.push(mkConn(P.code, '140.82.112.21', 443, 'api.github.com', { age: 5 * HOUR }));
      c.push(mkConn(P.steam, '23.36.163.47', 443, 'steamcommunity.com', { age: BOOT - 29 }));
      c.push(mkConn(P.apsd, '17.57.146.52', 5223, 'courier.push.apple.com', { age: BOOT - 30 }));
      c.push(mkConn(P.cloudd, '17.248.185.69', 443, 'gateway.icloud.com', { age: 2 * HOUR }));
      c.push(mkConn(P.nsurl, '17.253.53.207', 443, 'swdist.apple.com', { age: 4 * HOUR }));
      c.push(mkConn(P.trustd, '17.253.21.201', 80, 'ocsp2.apple.com', { status: 'TIME_WAIT' }));
      c.push(mkConn(P.tailscale, '18.196.164.18', 443, 'controlplane.tailscale.com', { age: BOOT - 33 }));
      c.push(mkConn(P.tailscale, '46.101.98.215', 443, 'derp4.tailscale.com', { age: BOOT - 33 }));
      c.push(mkConn(P.sshSess, PEER, 52731, PEER_HOST, { laddr: TS_IP, lport: 22, dir: 'in', age: 24 * MIN }));
      c.push(mkConn(P.ytdlp, '142.250.181.238', 443, 'www.youtube.com', { flags: ['unsigned'], age: 2 * HOUR + 5 * MIN }));
      c.push(mkConn(P.ytdlp, '173.194.182.70', 443, 'rr3---sn-4g5e6nsz.googlevideo.com', { flags: ['unsigned'], age: 2 * HOUR + 4 * MIN }));
      c.push(mkConn(P.dev, '140.82.113.3', 443, 'github.com', { status: 'TIME_WAIT' }));
      c.push(mkConn(P.npm, '104.16.30.34', 443, 'registry.npmjs.org', { age: 65 * MIN }));
      c.push(mkConn(P.pip, '151.101.64.223', 443, 'files.pythonhosted.org', { age: 52 * MIN }));
      c.push(mkConn(P.curl, '93.184.215.14', 443, 'example.com', { flags: ['lolbin'], status: 'CLOSE_WAIT', age: 25 * MIN }));
      c.push(mkConn(P.mal, C2, C2_PORT, null, { status: 'SYN_SENT', flags: ['blocklisted_ip', 'odd_port'], age: 47 * MIN }));
      return c;
    }
    function buildPool(P) {
      return [
        [P.safariNet, '142.250.187.234', 443, 'i.ytimg.com'], [P.safariNet, '104.16.85.20', 443, 'cdnjs.cloudflare.com'],
        [P.safariNet, '185.199.108.133', 443, 'raw.githubusercontent.com'], [P.chromeNet, '142.250.187.206', 443, 'clients4.google.com'],
        [P.slackNet, '52.29.238.212', 443, 'wss-backup.slack.com'], [P.spotify, '35.186.224.47', 443, 'gew4-spclient.spotify.com'],
        [P.cloudd, '17.248.185.71', 443, 'p52-ckdatabasews.icloud.com'], [P.mdns, LAN_GW, 53, null, 'UDP'],
      ];
    }
    function buildListening(P) {
      const L = mkListen;
      return [
        L(P.launchd, 'TCP', '0.0.0.0', 22, BOOT), L(P.cc, 'TCP', '0.0.0.0', 5000, BOOT - 34), L(P.cc, 'TCP', '0.0.0.0', 7000, BOOT - 34),
        L(P.rapportd, 'TCP', '0.0.0.0', 49152, BOOT - 35), L(P.mdns, 'UDP', '0.0.0.0', 5353, BOOT),
        L(P.spotify, 'UDP', '0.0.0.0', 57621, 2 * HOUR + 6 * MIN), L(P.dev, 'TCP', '0.0.0.0', 3000, 2 * HOUR + 44 * MIN),
        L(P.tailscale, 'TCP', TS_IP, 61473, BOOT - 33),
        L(P.engine, 'TCP', '127.0.0.1', 8777, ENGINE_UP), L(P.httpd, 'TCP', '127.0.0.1', 8790, 41 * MIN),
        L(P.spotify, 'TCP', '127.0.0.1', 4381, 2 * HOUR + 6 * MIN),
      ];
    }

    function buildAlerts(P) {
      const mal = ref('updsvc', MAL_PID);
      const list = [
        A(46, 'critical', 'network', `Connection to blocklisted IP ${C2}:${C2_PORT}`,
          'updsvc (invalid code signature) tried to reach a known malware server.',
          { first: 47 * MIN, last: 70, count: 14, process: mal, remote: { ip: C2, port: C2_PORT, host: null },
            details: { rule: 'blocklisted_ip', state: 'SYN_SENT', direction: 'out', blocklist_note: 'example C2 (demo data)', flags: ['blocklisted_ip', 'odd_port', 'sig_mismatch'] } }),
        A(47, 'high', 'persistence', 'New LaunchAgent: com.updsvc.agent',
          'A new LaunchAgent in ~/Library/LaunchAgents starts updsvc from a hidden folder at every login.',
          { last: 46 * MIN, process: mal,
            details: { rule: 'new_persistence', kind: 'launch_agent', location: `${HOME}Library/LaunchAgents/com.updsvc.agent.plist`, name: 'com.updsvc.agent', command: `"${UPDSVC}" --daemon`, flags: ['hidden_dir', 'sig_mismatch'] } }),
        A(45, 'medium', 'process', 'Program in a hidden folder: updsvc',
          'updsvc runs from ~/Library/Application Support/.updsvc and its code signature does not match the file.',
          { last: 47 * MIN, process: mal, details: { rule: 'hidden_dir', flags: ['hidden_dir', 'sig_mismatch'] } }),
        A(44, 'medium', 'process', 'Download piped to a shell: curl → sh',
          'curl fetched a script from example.com and piped it straight into sh.',
          { last: 25 * MIN, process: ref('curl', P.curl.pid), remote: { ip: '93.184.215.14', port: 443, host: 'example.com' },
            details: { rule: 'download_exec', parent: 'zsh', cmdline: 'curl -fsSL https://example.com/install.sh | sh', flags: ['lolbin'] } }),
        A(43, 'medium', 'process', 'Unsigned program in a hidden folder: camhelper',
          'camhelper has no code signature and runs from ~/.cache/.sys.',
          { last: 47 * MIN, process: ref('camhelper', P.cam.pid), details: { rule: 'hidden_dir', flags: ['unsigned', 'hidden_dir', 'user_writable_path'] } }),
        A(41, 'medium', 'network', `Inbound SSH connection from ${PEER}`,
          `A device on your Tailscale network (${PEER_HOST}) logged in over Remote Login (SSH).`,
          { first: 26 * HOUR, last: 24 * MIN, count: 2, status: 'allowed', process: ref('sshd-session', P.sshSess.pid), remote: { ip: PEER, port: 52731, host: PEER_HOST },
            details: { rule: 'inbound_connection', local: `${TS_IP}:22` } }),
        A(40, 'medium', 'network', 'Server listening on all interfaces: node:3000',
          'A development server (next dev -H 0.0.0.0) accepts connections on TCP 3000 from any network.',
          { last: 2 * HOUR + 44 * MIN, process: ref('node', P.dev.pid), details: { rule: 'exposed_listener', ports: '3000/tcp', flags: ['exposed'] } }),
        A(39, 'low', 'network', 'AirPlay Receiver listening on all interfaces: ControlCenter',
          'ControlCenter accepts connections on TCP 5000 and 7000. Turn AirPlay Receiver off in System Settings › General › AirDrop & Handoff if you do not use it.',
          { last: ENGINE_UP - 40, process: ref('ControlCenter', P.cc.pid), details: { rule: 'exposed_listener', ports: '5000/tcp, 7000/tcp', flags: ['exposed'] } }),
        A(38, 'medium', 'process', 'Unsigned app went online: yt-dlp_macos',
          'yt-dlp_macos has no code signature, runs from your home folder and holds 2 connections.',
          { first: 26 * HOUR, last: 2 * HOUR + 5 * MIN, count: 3, process: ref('yt-dlp_macos', P.ytdlp.pid), details: { rule: 'unsigned_network', flags: ['unsigned', 'user_writable_path'] } }),
        A(35, 'low', 'network', 'New destination for node: registry.npmjs.org', 'node connected to 104.16.30.34:443 for the first time.',
          { last: 65 * MIN, process: ref('node', P.npm.pid), remote: { ip: '104.16.30.34', port: 443, host: 'registry.npmjs.org' }, details: { rule: 'new_destination' } }),
        A(33, 'low', 'network', 'New listening port: python3 127.0.0.1:8790', 'Bound to loopback only, so it is not reachable from other machines.',
          { last: 41 * MIN, process: ref('python3', P.httpd.pid), details: { rule: 'new_listener', laddr: '127.0.0.1', lport: 8790 } }),
        A(31, 'low', 'network', 'New app online: Code', 'Code opened its first connection (marketplace.visualstudio.com).',
          { first: 9 * DAY, last: 9 * DAY, status: 'acknowledged', process: ref('Code', P.code.pid), remote: { ip: '13.107.42.18', port: 443, host: 'marketplace.visualstudio.com' }, details: { rule: 'new_app_online', flags: ['new_app'] } }),
        A(30, 'low', 'network', 'New destination: Code → api.github.com:443', 'Visual Studio Code connected to a new server.',
          { last: 110 * MIN, process: ref('Code', P.code.pid), remote: { ip: '140.82.112.21', port: 443, host: 'api.github.com' }, details: { rule: 'new_destination' } }),
        A(29, 'low', 'network', 'New destination: Telegram → 149.154.175.53:443', 'Telegram connected to another data centre.',
          { last: 2 * HOUR, process: ref('Telegram', P.telegram.pid), remote: { ip: '149.154.175.53', port: 443, host: null }, details: { rule: 'new_destination' } }),
        A(27, 'low', 'network', 'New app online: zoom.us', 'zoom.us connected to zoom.us for the first time.',
          { first: 6 * DAY, last: 6 * DAY, status: 'acknowledged', process: ref('zoom.us', P.zoom.pid), remote: { ip: '170.114.52.2', port: 443, host: 'zoom.us' }, details: { rule: 'new_app_online', flags: ['new_app'] } }),
      ];
      if (!FULL) {
        list.push(A(25, 'low', 'system', 'Engine running without administrator rights', 'Connections owned by other users and system services may show without a process name. Run PC Sentinel with administrator/root rights for more coverage.',
          { last: ENGINE_UP - 5, details: { rule: 'coverage_gap', monitor: 'network' } }));
      }
      return list;
    }

    function infoEvents(E) {
      E(BOOT, 'info', 'system', 'macOS started', 'macOS 15.1 (24B83).');
      E(BOOT - 40, 'info', 'account', `${USER} logged in`, 'Login window.');
      E(BOOT - 33, 'info', 'network', 'Tailscale connected', `This Mac is ${TS_IP} on the tailnet.`);
      E(26 * HOUR + 12 * MIN, 'info', 'system', 'Woke from sleep', '');
      E(4 * HOUR, 'info', 'system', 'XProtect data updated', 'Background security update from Apple.');
      E(25 * HOUR, 'info', 'persistence', 'Launch daemon changed: com.google.keystone.daemon', 'ProgramArguments now point at GoogleUpdater 141.0.7390.55.');
      E(2 * DAY + 1 * HOUR, 'info', 'persistence', 'Autostart baseline refreshed', '14 entries across LaunchAgents, LaunchDaemons, login items, cron and shell files.');
      E(41 * MIN, 'info', 'network', 'Listening: python3 127.0.0.1:8790', 'Loopback only.');
    }

    // privacy monitoring is not available on macOS (coverage_supported.privacy === false): no devices reported
    const buildPrivacy = () => ({ devices: {}, history: [] });

    function buildPersistence() {
      const it = mkPersist;
      const LA = `${HOME}Library/LaunchAgents/`;
      const GUPD = `${HOME}Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/MacOS/GoogleUpdater`;
      const MAU = '/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/Microsoft Update Assistant.app/Contents/MacOS/Microsoft Update Assistant';
      const LI = 'Login Items (System Settings › General › Login Items)';
      return [
        it('launch_agent', `${LA}com.updsvc.agent.plist`, 'com.updsvc.agent', `"${UPDSVC}" --daemon`, UPDSVC, 'Contoso Software Ltd.', 'HashMismatch', 'malicious', 'new', 46 * MIN, ['hidden_dir', 'sig_mismatch']),
        it('launch_agent', `${LA}io.pcsentinel.agent.plist`, 'io.pcsentinel.agent', `${HOME}src/pc-sentinel/.venv/bin/python3 main.py --tray`, PY, null, 'NotSigned', 'known', 'baseline', 2 * DAY),
        it('launch_agent', `${LA}com.google.keystone.agent.plist`, 'com.google.keystone.agent', `"${GUPD}" --wake`, GUPD, 'Google LLC', 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('launch_agent', '/Library/LaunchAgents/com.microsoft.update.agent.plist', 'com.microsoft.update.agent', `"${MAU}" --launchByAgent`, MAU, 'Microsoft Corporation', 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('launch_daemon', '/Library/LaunchDaemons/com.google.keystone.daemon.plist', 'com.google.keystone.daemon', `"${GUPD}" --server --system`, GUPD, 'Google LLC', 'Valid', 'trusted', 'changed', 25 * HOUR),
        it('launch_daemon', '/Library/LaunchDaemons/com.microsoft.autoupdate.helper.plist', 'com.microsoft.autoupdate.helper', '/Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper', '/Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper', 'Microsoft Corporation', 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('launch_daemon', '/Library/LaunchDaemons/com.example.vpnhelper.plist', 'com.example.vpnhelper', '/Library/PrivilegedHelperTools/com.example.vpnhelper', '/Library/PrivilegedHelperTools/com.example.vpnhelper', null, 'Unknown', 'known', 'removed', 30 * DAY, ['missing_file']),
        it('login_item', LI, 'Slack', '/Applications/Slack.app', img.Slack[0], 'Slack Technologies, Inc.', 'Valid', 'trusted', 'baseline', 30 * DAY),
        it('login_item', LI, 'Spotify', '/Applications/Spotify.app', img.Spotify[0], 'Spotify AB', 'Valid', 'trusted', 'baseline', 30 * DAY),
        it('login_item', LI, 'Telegram', '/Applications/Telegram.app', img.Telegram[0], 'Telegram FZ-LLC', 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('login_item', LI, 'Tailscale', '/Applications/Tailscale.app', img.Tailscale[0], 'Tailscale Inc.', 'Valid', 'trusted', 'baseline', 22 * DAY),
        it('cron', `crontab (${USER})`, '0 * * * * ~/bin/backup.sh', `${HOME}bin/backup.sh`, `${HOME}bin/backup.sh`, null, 'NotSigned', 'known', 'baseline', 20 * DAY),
        it('shell_rc', `${HOME}.zprofile`, 'line 3', 'eval "$(/opt/homebrew/bin/brew shellenv)"', '/opt/homebrew/bin/brew', null, 'NotSigned', 'known', 'baseline', 41 * DAY),
        it('shell_rc', `${HOME}.zshrc`, 'line 27', 'export PATH="$HOME/.local/bin:$PATH"', '', null, 'Unknown', 'known', 'changed', 25 * HOUR),
      ];
    }

    function buildFiles() {
      const AS = `${HOME}Library/Application Support/`;
      const W = (path, label, kind, exists) => ({ path, label, kind, audited: false, exists: exists !== false });
      return {
        watched: [
          W(`${HOME}Library/Keychains/login.keychain-db`, 'Login keychain', 'credential'),
          W(`${HOME}Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies`, 'Safari cookies', 'credential'),
          W(`${AS}Google/Chrome/Default/Login Data`, 'Chrome saved passwords', 'credential'),
          W(`${AS}Google/Chrome/Default/Cookies`, 'Chrome cookies', 'credential'),
          W(`${HOME}.git-credentials`, 'Git credentials', 'credential', false),
          W(`${HOME}.config/gh/hosts.yml`, 'GitHub CLI token', 'credential'),
          W(`${HOME}.ssh/id_ed25519`, 'SSH private key', 'ssh'),
          W(`${HOME}.ssh/known_hosts`, 'SSH known hosts', 'ssh'),
          W(`${AS}Exodus/exodus.wallet`, 'Exodus wallet', 'wallet', false),
          W(`${AS}Electrum/wallets`, 'Electrum wallets', 'wallet', false),
          W(`${HOME}Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram`, 'Telegram session', 'messenger'),
          W(`${HOME}Documents/Finance/wallet-seed-backup.txt`, 'Canary: wallet seed backup', 'canary', FILE_AUDIT),
          W(`${HOME}Desktop/passwords-old.xlsx`, 'Canary: passwords spreadsheet', 'canary', FILE_AUDIT),
          W(`${HOME}.aws/credentials`, 'Canary: AWS credentials', 'canary', FILE_AUDIT),
        ],
        access: [],
      };
    }

    return {
      platform: 'macos', os: 'macOS 15.1', osWord: 'macOS', img,
      protectedNames: ['kernel_task', 'launchd', 'WindowServer', 'loginwindow', 'logd', 'configd', 'mDNSResponder', 'coreaudiod'],
      supported: { processes: true, network: true, privacy: false, persistence: true, defender_log: false, security_log: false, dns_log: false, file_audit: false, canaries: true },
      coverage: () => ({ processes: true, network: true, privacy: false, persistence: true, defender_log: false, security_log: false, dns_log: false, file_audit: false, canaries: FILE_AUDIT ? 3 : 0 }),
      defender: () => null,
      autostart: { supported: true, enabled: true, detail: 'LaunchAgent (~/Library/LaunchAgents/io.pcsentinel.agent.plist)' },
      blockMessage: (ip) => `Firewall rule for ${ip}: requested. Enter an administrator password when macOS asks to apply it.`,
      buildProcesses, buildConnections, buildPool, buildListening, buildAlerts, infoEvents, buildPrivacy, buildPersistence, buildFiles,
      isAppStart: (p) => (p.ppid === 1 && p.user === USER && /^\/Applications\//.test(p.exe)) || ['node', 'python3', 'curl', 'yt-dlp_macos', 'Terminal', 'updsvc'].includes(p.name),
      eventApps: ['Safari', 'Google Chrome', 'Telegram', 'node', 'python3', 'Slack', 'Spotify', 'Code', 'git', 'ssh', 'zoom.us', 'steam_osx'],
      eventHosts: [['github.com', '140.82.113.3', 443], ['pypi.org', '151.101.0.223', 443], ['api.github.com', '140.82.112.21', 443], ['zoom.us', '170.114.52.2', 443],
        ['www.apple.com', '17.253.144.10', 443], ['149.154.167.51', '149.154.167.51', 443], ['www.youtube.com', '142.250.181.238', 443], ['registry.npmjs.org', '104.16.30.34', 443]],
      destExtra: [
        ['185.199.110.133', 'objects.githubusercontent.com', 443, 'node'], ['17.253.53.207', 'gs.apple.com', 443, 'nsurlsessiond'],
        ['17.248.185.69', 'gateway.icloud.com', 443, 'cloudd'], ['104.244.42.193', 'api.x.com', 443, 'Safari'],
        ['91.108.56.130', null, 443, 'Telegram'], [LAN_GW, null, 53, 'mDNSResponder'], ['8.8.8.8', 'dns.google', 443, 'Google Chrome'],
      ],
      allowlist: [
        { id: 4, kind: 'process', value: PY, note: 'PC Sentinel engine', ts: ago(2 * DAY) },
        { id: 3, kind: 'persistence', value: `${HOME}bin/backup.sh`, note: 'my hourly backup', ts: ago(5 * DAY) },
        { id: 2, kind: 'destination', value: PEER, note: 'my laptop over Tailscale (SSH)', ts: ago(6 * DAY) },
        { id: 1, kind: 'process', value: NODE, note: 'dev tool', ts: ago(9 * DAY) },
      ],
      dns: null,
      streamPool: (P) => [
        () => ({ severity: 'low', category: 'network', title: 'New destination: com.apple.WebKit.Networking → i.ytimg.com', summary: 'First connection from Safari to 142.250.187.234:443.', process: ref('com.apple.WebKit.Networking', P.safariNet.pid), remote: { ip: '142.250.187.234', port: 443, host: 'i.ytimg.com' }, details: { rule: 'new_destination' } }),
        () => ({ severity: 'medium', category: 'network', title: 'New exposed listener: python3 0.0.0.0:8000', summary: 'A quick file server (python3 -m http.server) is reachable from your LAN and tailnet.', process: ref('python3', P.pip.pid), details: { rule: 'exposed_listener', ports: '8000/tcp', flags: ['exposed'] } }),
        () => ({ severity: 'low', category: 'process', title: 'First-seen process: git-remote-https', summary: 'Started by git (Apple Command Line Tools).', process: { pid: rint(300, 99000), name: 'git-remote-https', exe: '/Library/Developer/CommandLineTools/usr/libexec/git-core/git-remote-https', signer: APPLE, sig_status: 'Valid', trust: 'trusted' }, details: { rule: 'first_seen', flags: ['first_seen'] } }),
        () => ({ severity: 'low', category: 'network', title: 'New destination: python3 → download.pytorch.org', summary: 'pip connected to 18.239.94.112:443.', process: ref('python3', P.pip.pid), remote: { ip: '18.239.94.112', port: 443, host: 'download.pytorch.org' }, details: { rule: 'new_destination' } }),
      ],
    };
  }

  /* ================================================================== profile: Linux */
  function linuxProfile() {
    const UBU = 'Ubuntu archive';
    const HOME = '/home/alex/';
    const UPDSVC = '/var/tmp/.updsvc/updsvc';
    const CAMHELPER = `${HOME}.cache/.sys/camhelper`;
    const PY = '/usr/bin/python3.12';
    const NODE = '/usr/bin/node';
    const ZOOM = '/opt/zoom/zoom';
    const FIREFOX = '/usr/bin/firefox';
    const img = {
      'systemd': ['/usr/lib/systemd/systemd', UBU, 'Valid', 'trusted'],
      'kthreadd': ['', UBU, 'Valid', 'trusted'],
      'systemd-journald': ['/usr/lib/systemd/systemd-journald', UBU, 'Valid', 'trusted'],
      'systemd-udevd': ['/usr/lib/systemd/systemd-udevd', UBU, 'Valid', 'trusted'],
      'systemd-resolved': ['/usr/lib/systemd/systemd-resolved', UBU, 'Valid', 'trusted'],
      'systemd-timesyncd': ['/usr/lib/systemd/systemd-timesyncd', UBU, 'Valid', 'trusted'],
      'systemd-logind': ['/usr/lib/systemd/systemd-logind', UBU, 'Valid', 'trusted'],
      'dbus-daemon': ['/usr/bin/dbus-daemon', UBU, 'Valid', 'trusted'],
      'NetworkManager': ['/usr/sbin/NetworkManager', UBU, 'Valid', 'trusted'],
      'avahi-daemon': ['/usr/sbin/avahi-daemon', UBU, 'Valid', 'trusted'],
      'cupsd': ['/usr/sbin/cupsd', UBU, 'Valid', 'trusted'],
      'sshd': ['/usr/sbin/sshd', UBU, 'Valid', 'trusted'],
      'cron': ['/usr/sbin/cron', UBU, 'Valid', 'trusted'],
      'snapd': ['/usr/lib/snapd/snapd', UBU, 'Valid', 'trusted'],
      'polkitd': ['/usr/lib/polkit-1/polkitd', UBU, 'Valid', 'trusted'],
      'gdm3': ['/usr/sbin/gdm3', UBU, 'Valid', 'trusted'],
      'gnome-shell': ['/usr/bin/gnome-shell', UBU, 'Valid', 'trusted'],
      'Xwayland': ['/usr/bin/Xwayland', UBU, 'Valid', 'trusted'],
      'pipewire': ['/usr/bin/pipewire', UBU, 'Valid', 'trusted'],
      'wireplumber': ['/usr/bin/wireplumber', UBU, 'Valid', 'trusted'],
      'pipewire-pulse': ['/usr/bin/pipewire-pulse', UBU, 'Valid', 'trusted'],
      'gnome-terminal-server': ['/usr/libexec/gnome-terminal-server', UBU, 'Valid', 'trusted'],
      'bash': ['/usr/bin/bash', UBU, 'Valid', 'trusted'],
      'sh': ['/usr/bin/dash', UBU, 'Valid', 'trusted'],
      'curl': ['/usr/bin/curl', UBU, 'Valid', 'trusted'],
      'firefox': [FIREFOX, 'Mozilla Corporation', 'Valid', 'trusted'],
      'Isolated Web Co': [FIREFOX, 'Mozilla Corporation', 'Valid', 'trusted'],
      'slack': ['/usr/lib/slack/slack', 'Slack Technologies, Inc.', 'Valid', 'trusted'],
      'zoom': [ZOOM, 'Zoom Video Communications, Inc.', 'Valid', 'trusted'],
      'telegram-desktop': ['/usr/bin/telegram-desktop', UBU, 'Valid', 'trusted'],
      'code': ['/usr/share/code/code', 'Microsoft Corporation', 'Valid', 'trusted'],
      'spotify': ['/usr/share/spotify/spotify', 'Spotify AB', 'Valid', 'trusted'],
      'steam': [`${HOME}.local/share/Steam/ubuntu12_32/steam`, 'Valve Corporation', 'Valid', 'known'],
      'tailscaled': ['/usr/sbin/tailscaled', 'Tailscale Inc.', 'Valid', 'trusted'],
      'node': [NODE, UBU, 'Valid', 'trusted'],
      'python3': [PY, UBU, 'Valid', 'trusted'],
      'yt-dlp': [`${HOME}.local/bin/yt-dlp`, null, 'NotSigned', 'unsigned'],
      'updsvc': [UPDSVC, null, 'NotSigned', 'malicious'],
    };

    function buildProcesses() {
      const { procs, add, child } = treeBuilder({ reserved: [1, 2, MAL_PID], pid: () => rint(400, 250000) });
      const P = {};
      const systemd = P.systemd = add('systemd', { pid: 1, user: 'root', age: BOOT, mem: 13, cmd: '/sbin/init splash', cpu: 0.1 });
      add('kthreadd', { pid: 2, user: 'root', age: BOOT, mem: 0, cmd: '' });
      const sysd = (name, user, o) => child(systemd, name, Object.assign({ user, age: rint(BOOT - 30, BOOT - 2) }, o || {}));
      sysd('systemd-journald', 'root', { mem: 32 });
      sysd('systemd-udevd', 'root', { mem: 9 });
      P.resolved = sysd('systemd-resolved', 'systemd-resolve', { mem: 13 });
      sysd('systemd-timesyncd', 'systemd-timesync', { mem: 7 });
      sysd('systemd-logind', 'root', { mem: 8 });
      sysd('dbus-daemon', 'messagebus', { mem: 6, cmd: '@dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only' });
      P.nm = sysd('NetworkManager', 'root', { mem: 21, cmd: '/usr/sbin/NetworkManager --no-daemon' });
      P.avahi = sysd('avahi-daemon', 'avahi', { mem: 4, cmd: 'avahi-daemon: running [workstation-01.local]' });
      P.cups = sysd('cupsd', 'root', { mem: 12, cmd: '/usr/sbin/cupsd -l' });
      P.sshd = sysd('sshd', 'root', { mem: 9, cmd: 'sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups' });
      P.sshSess = child(P.sshd, 'sshd', { user: 'root', age: 24 * MIN, mem: 11, cpu: 0.1, cmd: `sshd: ${USER} [priv]` });
      child(P.sshSess, 'sshd', { age: 24 * MIN, mem: 7, cmd: `sshd: ${USER}@pts/2` });
      sysd('cron', 'root', { mem: 3, cmd: '/usr/sbin/cron -f -P' });
      P.snapd = sysd('snapd', 'root', { mem: 38 });
      sysd('polkitd', 'polkitd', { mem: 10, cmd: '/usr/lib/polkit-1/polkitd --no-debug' });
      P.tailscaled = sysd('tailscaled', 'root', { age: BOOT - 20, mem: 46, cpu: 0.1, cmd: '/usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/run/tailscale/tailscaled.sock --port=41641' });
      sysd('gdm3', 'root', { mem: 10 });

      const usd = child(systemd, 'systemd', { age: BOOT - 45, mem: 11, cmd: '/usr/lib/systemd/systemd --user' });
      const shell = child(usd, 'gnome-shell', { age: BOOT - 44, mem: 380, cpu: 2.6 });
      child(shell, 'Xwayland', { age: BOOT - 44, mem: 70, cpu: 0.4, cmd: '/usr/bin/Xwayland :0 -rootless -noreset -accessx -core -auth /run/user/1000/.mutter-Xwaylandauth.K3Q1Z2 -listenfd 4 -listenfd 5 -displayfd 6' });
      child(usd, 'pipewire', { age: BOOT - 44, mem: 12, cpu: 0.3 });
      child(usd, 'wireplumber', { age: BOOT - 44, mem: 17 });
      child(usd, 'pipewire-pulse', { age: BOOT - 44, mem: 9, cpu: 0.2 });
      child(usd, 'dbus-daemon', { age: BOOT - 44, mem: 5, cmd: '/usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only' });

      P.firefox = child(shell, 'firefox', { age: 4 * HOUR, mem: 420, cpu: 0.9 });
      P.firefoxNet = child(P.firefox, 'firefox', { age: 4 * HOUR, mem: 30, cpu: 0.3, cmd: `${FIREFOX} -contentproc -parentBuildID 20251020151632 -sandboxReporter 4 -ipcHandle 0 -initialChannelId {0d1f6c2a-4b3e-4f7a-9c8d-2e1b5a6f7c3d} -parentPid 0 -appDir /usr/lib/firefox/browser 3 socket` });
      for (let i = 0; i < 6; i++) child(P.firefox, 'Isolated Web Co', { age: rint(5 * MIN, 4 * HOUR), mem: rint(80, 420), cpu: i ? 0.1 : 2.2, cmd: `${FIREFOX} -contentproc -isForBrowser -prefsLen 31211 -prefMapSize 244787 ${4 + i} tab` });
      P.slack = child(shell, 'slack', { age: BOOT - 40, mem: 200, cpu: 0.3, cmd: '/usr/lib/slack/slack --startup' });
      for (let i = 0; i < 3; i++) child(P.slack, 'slack', { age: BOOT - 40, mem: rint(60, 300), cmd: `/usr/lib/slack/slack --type=${i ? 'renderer' : 'utility'} --enable-crash-reporter` });
      P.zoom = child(shell, 'zoom', { age: 36 * MIN, mem: 360, cpu: 7.4 });
      P.telegram = child(shell, 'telegram-desktop', { age: BOOT - 39, mem: 170, cpu: 0.2, cmd: 'telegram-desktop -autostart' });
      P.code = child(shell, 'code', { age: 6 * HOUR, mem: 250, cpu: 0.6 });
      for (let i = 0; i < 3; i++) child(P.code, 'code', { age: 6 * HOUR, mem: rint(80, 460), cpu: i ? 0.2 : 1.3, cmd: `/usr/share/code/code --type=${i ? 'renderer' : 'utility'}` });
      P.spotify = child(shell, 'spotify', { age: 2 * HOUR + 6 * MIN, mem: 230, cpu: 0.9 });
      P.steam = child(shell, 'steam', { age: BOOT - 38, mem: 140, cpu: 0.3, flags: ['user_writable_path'] });

      const term = child(usd, 'gnome-terminal-server', { age: 3 * HOUR + 20 * MIN, mem: 58, cpu: 0.1 });
      const b1 = child(term, 'bash', { age: 3 * HOUR + 20 * MIN, mem: 5, cmd: 'bash' });
      const b2 = child(term, 'bash', { age: 58 * MIN, mem: 5, cmd: 'bash' });
      P.engine = child(b1, 'python3', { age: ENGINE_UP, mem: 70, cpu: 0.9, cmd: `${HOME}src/pc-sentinel/.venv/bin/python3 main.py --port 8777` });
      P.httpd = child(b2, 'python3', { age: 41 * MIN, mem: 20, cmd: `python3 -m http.server 8790 --bind 127.0.0.1 --directory ${HOME}src/pc-sentinel/dashboard` });
      P.dev = child(b1, 'node', { age: 2 * HOUR + 44 * MIN, mem: 110, cpu: 0.2, cmd: `node ${HOME}src/webapp/node_modules/.bin/next dev -H 0.0.0.0 -p 3000` });
      P.npm = child(b1, 'node', { age: 66 * MIN, mem: 86, cpu: 0.1, cmd: 'node /usr/bin/npm install' });
      P.pip = child(b2, 'python3', { age: 53 * MIN, mem: 190, cpu: 0.4, cmd: 'python3 -m pip install --user --upgrade torch torchvision' });
      P.ytdlp = child(b2, 'yt-dlp', { age: 2 * HOUR + 5 * MIN, mem: 55, cpu: 0.6, flags: ['unsigned', 'user_writable_path'], cmd: `/usr/bin/python3 ${HOME}.local/bin/yt-dlp -x --audio-format mp3 https://www.youtube.com/watch?v=aqz-KE-bpKQ` });
      P.curl = child(b2, 'curl', { age: 25 * MIN, mem: 6, flags: ['lolbin'], cmd: 'curl -fsSL https://example.com/install.sh' });
      child(b2, 'sh', { age: 25 * MIN, mem: 2, cmd: 'sh' });

      P.mal = child(usd, 'updsvc', { pid: MAL_PID, age: 47 * MIN, mem: 23, cpu: 0.1, cmd: `${UPDSVC} --daemon`, flags: ['hidden_dir', 'user_writable_path', 'padded_binary'] });
      return { procs, P };
    }

    function buildConnections(P) {
      const c = [];
      [
        ['142.250.181.206', 443, 'www.google.com'], ['142.250.181.238', 443, 'www.youtube.com'], ['140.82.114.26', 443, 'alive.github.com'],
        ['104.18.32.47', 443, 'github.githubassets.com'], ['151.101.1.140', 443, 'www.reddit.com'], ['208.80.154.224', 443, 'en.wikipedia.org'],
        ['34.107.243.93', 443, 'push.services.mozilla.com'], ['172.217.19.110', 443, 'mail.google.com'], ['142.250.185.78', 443, 'meet.google.com'],
        ['151.101.193.69', 443, 'stackoverflow.com'],
      ].forEach(([ip, port, host]) => c.push(mkConn(P.firefoxNet, ip, port, host)));
      [
        ['52.29.238.212', 443, 'wss-primary.slack.com'], ['18.66.218.31', 443, 'edgeapi.slack.com'], ['35.157.212.10', 443, 'files.slack.com'],
      ].forEach(([ip, port, host]) => c.push(mkConn(P.slack, ip, port, host, { age: rint(10 * MIN, BOOT - 40) })));
      c.push(mkConn(P.zoom, '170.114.52.2', 443, 'zoom.us', { age: 36 * MIN }));
      c.push(mkConn(P.zoom, '170.114.10.86', 8801, null, { proto: 'UDP', age: 34 * MIN }));
      c.push(mkConn(P.telegram, '149.154.167.51', 443, null));
      c.push(mkConn(P.telegram, '149.154.175.53', 443, null, { age: 2 * HOUR }));
      c.push(mkConn(P.code, '13.107.42.18', 443, 'marketplace.visualstudio.com', { age: 6 * HOUR }));
      c.push(mkConn(P.code, '140.82.112.21', 443, 'api.github.com', { age: 5 * HOUR }));
      c.push(mkConn(P.spotify, '35.186.224.25', 443, 'spclient.wg.spotify.com', { age: 2 * HOUR }));
      c.push(mkConn(P.spotify, '104.199.65.124', 4070, 'ap-gew4.spotify.com', { age: 2 * HOUR }));
      c.push(mkConn(P.steam, '23.36.163.47', 443, 'steamcommunity.com', { age: BOOT - 38 }));
      c.push(mkConn(P.snapd, '185.125.188.58', 443, 'api.snapcraft.io', { age: 3 * HOUR }));
      c.push(mkConn(P.nm, '185.125.190.48', 80, 'connectivity-check.ubuntu.com', { status: 'TIME_WAIT' }));
      c.push(mkConn(P.tailscaled, '18.196.164.18', 443, 'controlplane.tailscale.com', { age: BOOT - 20 }));
      c.push(mkConn(P.tailscaled, '46.101.98.215', 443, 'derp4.tailscale.com', { age: BOOT - 20 }));
      c.push(mkConn(P.sshSess, PEER, 52731, PEER_HOST, { laddr: TS_IP, lport: 22, dir: 'in', age: 24 * MIN }));
      c.push(mkConn(P.ytdlp, '142.250.181.238', 443, 'www.youtube.com', { flags: ['unsigned'], age: 2 * HOUR + 5 * MIN }));
      c.push(mkConn(P.ytdlp, '173.194.182.70', 443, 'rr3---sn-4g5e6nsz.googlevideo.com', { flags: ['unsigned'], age: 2 * HOUR + 4 * MIN }));
      c.push(mkConn(P.dev, '140.82.113.3', 443, 'github.com', { status: 'TIME_WAIT' }));
      c.push(mkConn(P.npm, '104.16.30.34', 443, 'registry.npmjs.org', { age: 65 * MIN }));
      c.push(mkConn(P.pip, '151.101.64.223', 443, 'files.pythonhosted.org', { age: 52 * MIN }));
      c.push(mkConn(P.curl, '93.184.215.14', 443, 'example.com', { flags: ['lolbin'], status: 'CLOSE_WAIT', age: 25 * MIN }));
      c.push(mkConn(P.mal, C2, C2_PORT, null, { status: 'SYN_SENT', flags: ['blocklisted_ip', 'odd_port'], age: 47 * MIN }));
      return c;
    }
    function buildPool(P) {
      return [
        [P.firefoxNet, '142.250.187.234', 443, 'i.ytimg.com'], [P.firefoxNet, '104.16.85.20', 443, 'cdnjs.cloudflare.com'],
        [P.firefoxNet, '185.199.108.133', 443, 'raw.githubusercontent.com'], [P.firefoxNet, '34.120.208.123', 443, 'firefox.settings.services.mozilla.com'],
        [P.slack, '52.29.238.212', 443, 'wss-backup.slack.com'], [P.spotify, '35.186.224.47', 443, 'gew4-spclient.spotify.com'],
        [P.resolved, LAN_GW, 53, null, 'UDP'],
      ];
    }
    function buildListening(P) {
      const L = mkListen;
      return [
        L(P.sshd, 'TCP', '0.0.0.0', 22, BOOT), L(P.avahi, 'UDP', '0.0.0.0', 5353, BOOT), L(P.spotify, 'UDP', '0.0.0.0', 57621, 2 * HOUR + 6 * MIN),
        L(P.dev, 'TCP', '0.0.0.0', 3000, 2 * HOUR + 44 * MIN), L(P.tailscaled, 'UDP', '0.0.0.0', 41641, BOOT - 20),
        L(P.resolved, 'TCP', '127.0.0.53', 53, BOOT), L(P.resolved, 'UDP', '127.0.0.53', 53, BOOT), L(P.resolved, 'TCP', '127.0.0.54', 53, BOOT),
        L(P.cups, 'TCP', '127.0.0.1', 631, BOOT), L(P.tailscaled, 'TCP', TS_IP, 61473, BOOT - 20),
        L(P.engine, 'TCP', '127.0.0.1', 8777, ENGINE_UP), L(P.httpd, 'TCP', '127.0.0.1', 8790, 41 * MIN),
        L(P.spotify, 'TCP', '127.0.0.1', 4381, 2 * HOUR + 6 * MIN),
      ];
    }

    function buildAlerts(P) {
      const mal = ref('updsvc', MAL_PID);
      const list = [
        A(46, 'critical', 'network', `Connection to blocklisted IP ${C2}:${C2_PORT}`,
          'updsvc (not from any package, known-bad hash) tried to reach a known malware server.',
          { first: 47 * MIN, last: 70, count: 14, process: mal, remote: { ip: C2, port: C2_PORT, host: null },
            details: { rule: 'blocklisted_ip', state: 'SYN_SENT', direction: 'out', blocklist_note: 'example C2 (demo data)', flags: ['blocklisted_ip', 'odd_port'] } }),
        A(47, 'high', 'persistence', 'New systemd user unit: updsvc.service',
          'A new user service in ~/.config/systemd/user starts /var/tmp/.updsvc/updsvc at every login.',
          { last: 46 * MIN, process: mal,
            details: { rule: 'new_persistence', kind: 'systemd_unit', location: `${HOME}.config/systemd/user/updsvc.service`, name: 'updsvc.service', command: `${UPDSVC} --daemon`, flags: ['hidden_dir', 'user_writable_path'] } }),
        A(48, 'high', 'persistence', 'New cron job: @reboot /var/tmp/.updsvc/updsvc',
          `A new line in ${USER}'s crontab restarts updsvc after every reboot.`,
          { last: 45 * MIN, process: mal,
            details: { rule: 'new_persistence', kind: 'cron', location: `/var/spool/cron/crontabs/${USER}`, name: '@reboot /var/tmp/.updsvc/updsvc', command: UPDSVC, flags: ['hidden_dir'] } }),
        A(45, 'medium', 'process', 'Padded executable: updsvc (612 MB, 97% zero bytes)',
          'Malware often pads files past antivirus upload limits. The file is not owned by any installed package.',
          { last: 47 * MIN, process: mal, details: { rule: 'padded_binary', size_mb: 612, zero_ratio: 0.97, flags: ['padded_binary', 'hidden_dir'] } }),
        A(44, 'medium', 'process', 'Download piped to a shell: curl → sh',
          'curl fetched a script from example.com and piped it straight into sh.',
          { last: 25 * MIN, process: ref('curl', P.curl.pid), remote: { ip: '93.184.215.14', port: 443, host: 'example.com' },
            details: { rule: 'download_exec', parent: 'bash', cmdline: 'curl -fsSL https://example.com/install.sh | sh', flags: ['lolbin'] } }),
        A(43, 'high', 'privacy', 'Webcam used by camhelper from a hidden folder',
          'camhelper (~/.cache/.sys/…) had /dev/video0 open for 22 s, 19 days ago. The file is gone now.',
          { last: ENGINE_UP - 50, process: { pid: null, name: 'camhelper', exe: CAMHELPER, signer: null, sig_status: 'Unknown', trust: 'malicious' },
            details: { rule: 'privacy_hidden_dir', device: 'webcam', start: ago(CAM_AGO), stop: ago(CAM_AGO - 22), source: '/dev/video0', file_exists: false, flags: ['hidden_dir', 'user_writable_path'] } }),
        A(41, 'medium', 'network', `Inbound SSH connection to sshd:22 from ${PEER}`,
          `A device on your Tailscale network (${PEER_HOST}) logged in over SSH.`,
          { first: 26 * HOUR, last: 24 * MIN, count: 2, status: 'allowed', process: ref('sshd', P.sshSess.pid), remote: { ip: PEER, port: 52731, host: PEER_HOST },
            details: { rule: 'inbound_connection', local: `${TS_IP}:22` } }),
        A(40, 'medium', 'network', 'Server listening on all interfaces: node:3000',
          'A development server (next dev -H 0.0.0.0) accepts connections on TCP 3000 from any network.',
          { last: 2 * HOUR + 44 * MIN, process: ref('node', P.dev.pid), details: { rule: 'exposed_listener', ports: '3000/tcp', flags: ['exposed'] } }),
        A(39, 'low', 'network', 'OpenSSH server listening on all interfaces: sshd',
          'sshd accepts connections on TCP 22 from any network. Expected if you use SSH; limit it to your tailnet otherwise.',
          { last: ENGINE_UP - 40, process: ref('sshd', P.sshd.pid), details: { rule: 'exposed_listener', ports: '22/tcp', flags: ['exposed'] } }),
        A(38, 'medium', 'process', 'Unsigned app went online: yt-dlp',
          'yt-dlp is not from any package, runs from ~/.local/bin and holds 2 connections.',
          { first: 26 * HOUR, last: 2 * HOUR + 5 * MIN, count: 3, process: ref('yt-dlp', P.ytdlp.pid), details: { rule: 'unsigned_network', flags: ['unsigned', 'user_writable_path'] } }),
        A(35, 'low', 'network', 'New destination for node: registry.npmjs.org', 'node connected to 104.16.30.34:443 for the first time.',
          { last: 65 * MIN, process: ref('node', P.npm.pid), remote: { ip: '104.16.30.34', port: 443, host: 'registry.npmjs.org' }, details: { rule: 'new_destination' } }),
        A(34, 'low', 'privacy', 'Microphone in use: zoom', 'Zoom started recording audio.',
          { last: 34 * MIN, status: 'allowed', process: ref('zoom', P.zoom.pid), details: { rule: 'device_in_use', device: 'microphone' } }),
        A(33, 'low', 'network', 'New listening port: python3 127.0.0.1:8790', 'Bound to loopback only, so it is not reachable from other machines.',
          { last: 41 * MIN, process: ref('python3', P.httpd.pid), details: { rule: 'new_listener', laddr: '127.0.0.1', lport: 8790 } }),
        A(31, 'low', 'network', 'New app online: code', 'code opened its first connection (marketplace.visualstudio.com).',
          { first: 9 * DAY, last: 9 * DAY, status: 'acknowledged', process: ref('code', P.code.pid), remote: { ip: '13.107.42.18', port: 443, host: 'marketplace.visualstudio.com' }, details: { rule: 'new_app_online', flags: ['new_app'] } }),
        A(30, 'low', 'network', 'New destination: code → api.github.com:443', 'Visual Studio Code connected to a new server.',
          { last: 110 * MIN, process: ref('code', P.code.pid), remote: { ip: '140.82.112.21', port: 443, host: 'api.github.com' }, details: { rule: 'new_destination' } }),
        A(29, 'low', 'network', 'New destination: telegram-desktop → 149.154.175.53:443', 'Telegram connected to another data centre.',
          { last: 2 * HOUR, process: ref('telegram-desktop', P.telegram.pid), remote: { ip: '149.154.175.53', port: 443, host: null }, details: { rule: 'new_destination' } }),
        A(27, 'low', 'network', 'New app online: zoom', 'zoom connected to zoom.us for the first time.',
          { first: 6 * DAY, last: 6 * DAY, status: 'acknowledged', process: ref('zoom', P.zoom.pid), remote: { ip: '170.114.52.2', port: 443, host: 'zoom.us' }, details: { rule: 'new_app_online', flags: ['new_app'] } }),
      ];
      if (!FULL) {
        list.push(A(25, 'low', 'system', 'Engine running without root', 'Sockets owned by other users and system services show without a process name. Run PC Sentinel with administrator/root rights for more coverage.',
          { last: ENGINE_UP - 5, details: { rule: 'coverage_gap', monitor: 'network' } }));
      }
      return list;
    }

    function infoEvents(E) {
      E(BOOT, 'info', 'system', 'System booted', 'Ubuntu 24.04.1 LTS, Linux 6.8.0-47-generic.');
      E(BOOT - 45, 'info', 'account', `${USER} logged in`, 'GNOME session (Wayland).');
      E(BOOT - 20, 'info', 'network', 'Tailscale connected', `This PC is ${TS_IP} on the tailnet.`);
      E(26 * HOUR + 12 * MIN, 'info', 'system', 'Resumed from suspend', '');
      E(5 * HOUR, 'info', 'system', 'Packages upgraded', '12 packages upgraded by unattended-upgrades.');
      E(34 * MIN, 'info', 'privacy', 'Microphone in use: zoom', 'Video call.');
      E(21 * HOUR + 4 * MIN, 'info', 'privacy', 'Camera in use: telegram-desktop', 'Video call.');
      E(20 * HOUR + 46 * MIN, 'info', 'privacy', 'Camera released: telegram-desktop', 'In use for 18m 12s.');
      E(25 * HOUR, 'info', 'persistence', 'Shell startup file changed: ~/.bashrc', 'A PATH line was added.');
      E(2 * DAY + 1 * HOUR, 'info', 'persistence', 'Autostart baseline refreshed', '13 entries across systemd units, XDG autostart, cron and shell files.');
      E(41 * MIN, 'info', 'network', 'Listening: python3 127.0.0.1:8790', 'Loopback only.');
    }

    // Linux reports camera and microphone live; location and screen capture are not reported (keys absent)
    function buildPrivacy() {
      return {
        devices: {
          webcam: { in_use: false, by: [] },
          microphone: { in_use: true, by: ['zoom'] },
        },
        history: [
          { device: 'microphone', app: 'zoom', path: ZOOM, start: ago(34 * MIN), stop: null, in_use: true, trust: 'trusted', allowed: true },
          { device: 'webcam', app: 'zoom', path: ZOOM, start: ago(5 * HOUR + 2 * MIN), stop: ago(4 * HOUR + 31 * MIN), in_use: false, trust: 'trusted', allowed: true },
          { device: 'webcam', app: 'telegram-desktop', path: '/usr/bin/telegram-desktop', start: ago(21 * HOUR + 4 * MIN), stop: ago(20 * HOUR + 46 * MIN), in_use: false, trust: 'trusted', allowed: false },
          { device: 'microphone', app: 'telegram-desktop', path: '/usr/bin/telegram-desktop', start: ago(21 * HOUR + 4 * MIN), stop: ago(20 * HOUR + 46 * MIN), in_use: false, trust: 'trusted', allowed: false },
          { device: 'microphone', app: 'firefox', path: FIREFOX, start: ago(2 * DAY + 7 * HOUR), stop: ago(2 * DAY + 7 * HOUR - 372), in_use: false, trust: 'trusted', allowed: false },
          { device: 'webcam', app: 'camhelper', path: CAMHELPER, start: ago(CAM_AGO), stop: ago(CAM_AGO - 22), in_use: false, trust: 'unknown (file gone)', allowed: false },
        ],
      };
    }

    function buildPersistence() {
      const it = mkPersist;
      const AUT = `${HOME}.config/autostart/`;
      return [
        it('systemd_unit', `${HOME}.config/systemd/user/updsvc.service`, 'updsvc.service', `${UPDSVC} --daemon`, UPDSVC, null, 'NotSigned', 'malicious', 'new', 46 * MIN, ['hidden_dir', 'user_writable_path']),
        it('systemd_unit', '/usr/lib/systemd/system/ssh.service', 'ssh.service', '/usr/sbin/sshd -D', '/usr/sbin/sshd', UBU, 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('systemd_unit', '/usr/lib/systemd/system/tailscaled.service', 'tailscaled.service', '/usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state --socket=/run/tailscale/tailscaled.sock --port=41641', '/usr/sbin/tailscaled', 'Tailscale Inc.', 'Valid', 'trusted', 'baseline', 22 * DAY),
        it('systemd_unit', '/usr/lib/systemd/system/snapd.service', 'snapd.service', '/usr/lib/snapd/snapd', '/usr/lib/snapd/snapd', UBU, 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('systemd_unit', '/etc/systemd/system/old-backup.service', 'old-backup.service', `${HOME}bin/old-backup.sh`, `${HOME}bin/old-backup.sh`, null, 'Unknown', 'known', 'removed', 30 * DAY, ['missing_file']),
        it('xdg_autostart', `${AUT}pc-sentinel.desktop`, 'PC Sentinel', `${HOME}src/pc-sentinel/.venv/bin/python3 main.py --tray`, PY, UBU, 'Valid', 'known', 'baseline', 2 * DAY),
        it('xdg_autostart', `${AUT}slack.desktop`, 'Slack', '/usr/bin/slack --startup', '/usr/lib/slack/slack', 'Slack Technologies, Inc.', 'Valid', 'trusted', 'baseline', 30 * DAY),
        it('xdg_autostart', `${AUT}telegram-desktop.desktop`, 'Telegram', 'telegram-desktop -autostart', '/usr/bin/telegram-desktop', UBU, 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('xdg_autostart', '/etc/xdg/autostart/gnome-keyring-ssh.desktop', 'SSH Key Agent', '/usr/bin/gnome-keyring-daemon --start --components=ssh', '/usr/bin/gnome-keyring-daemon', UBU, 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('cron', `/var/spool/cron/crontabs/${USER}`, '@reboot /var/tmp/.updsvc/updsvc', UPDSVC, UPDSVC, null, 'NotSigned', 'malicious', 'new', 45 * MIN, ['hidden_dir']),
        it('cron', '/etc/cron.daily/apt-compat', 'apt-compat', '/etc/cron.daily/apt-compat', '/etc/cron.daily/apt-compat', UBU, 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('cron', '/etc/cron.d/e2scrub_all', 'e2scrub_all', '/sbin/e2scrub_all -A -r', '/usr/sbin/e2scrub_all', UBU, 'Valid', 'trusted', 'baseline', 41 * DAY),
        it('shell_rc', `${HOME}.bashrc`, 'line 118', 'export PATH="$HOME/.local/bin:$PATH"', '', null, 'Unknown', 'known', 'changed', 25 * HOUR),
        it('shell_rc', `${HOME}.profile`, 'line 22', '. "$HOME/.cargo/env"', `${HOME}.cargo/env`, null, 'NotSigned', 'known', 'baseline', 41 * DAY),
      ];
    }

    function buildFiles() {
      const W = (path, label, kind, exists) => ({ path, label, kind, audited: false, exists: exists !== false });
      return {
        watched: [
          W(`${HOME}.mozilla/firefox/k3j2h1g0.default-release/logins.json`, 'Firefox saved passwords', 'credential'),
          W(`${HOME}.mozilla/firefox/k3j2h1g0.default-release/key4.db`, 'Firefox key database', 'credential'),
          W(`${HOME}.mozilla/firefox/k3j2h1g0.default-release/cookies.sqlite`, 'Firefox cookies', 'credential'),
          W(`${HOME}.config/google-chrome/Default/Login Data`, 'Chrome saved passwords', 'credential', false),
          W(`${HOME}.local/share/keyrings/login.keyring`, 'GNOME login keyring', 'credential'),
          W(`${HOME}.git-credentials`, 'Git credentials', 'credential'),
          W(`${HOME}.config/gh/hosts.yml`, 'GitHub CLI token', 'credential'),
          W(`${HOME}.ssh/id_ed25519`, 'SSH private key', 'ssh'),
          W(`${HOME}.ssh/known_hosts`, 'SSH known hosts', 'ssh'),
          W(`${HOME}.config/Exodus/exodus.wallet`, 'Exodus wallet', 'wallet', false),
          W(`${HOME}.electrum/wallets`, 'Electrum wallets', 'wallet', false),
          W(`${HOME}.local/share/TelegramDesktop/tdata`, 'Telegram session (tdata)', 'messenger'),
          W(`${HOME}Documents/Finance/wallet-seed-backup.txt`, 'Canary: wallet seed backup', 'canary', FILE_AUDIT),
          W(`${HOME}Desktop/passwords-old.xlsx`, 'Canary: passwords spreadsheet', 'canary', FILE_AUDIT),
          W(`${HOME}.aws/credentials`, 'Canary: AWS credentials', 'canary', FILE_AUDIT),
        ],
        access: [],
      };
    }

    return {
      platform: 'linux', os: 'Ubuntu 24.04.1 LTS', osWord: 'Linux', img,
      protectedNames: ['systemd', 'kthreadd', 'systemd-journald', 'systemd-logind', 'dbus-daemon', 'gnome-shell', 'Xwayland'],
      supported: { processes: true, network: true, privacy: true, persistence: true, defender_log: false, security_log: false, dns_log: false, file_audit: false, canaries: true },
      coverage: () => ({ processes: true, network: true, privacy: true, persistence: true, defender_log: false, security_log: false, dns_log: false, file_audit: false, canaries: FILE_AUDIT ? 3 : 0 }),
      defender: () => null,
      autostart: { supported: true, enabled: true, detail: 'XDG autostart entry (~/.config/autostart/pc-sentinel.desktop)' },
      blockMessage: (ip) => `Firewall rule for ${ip}: requested. Authenticate when your desktop asks (polkit) to apply it.`,
      buildProcesses, buildConnections, buildPool, buildListening, buildAlerts, infoEvents, buildPrivacy, buildPersistence, buildFiles,
      isAppStart: (p) => (p.parent === 'gnome-shell' && p.user === USER) || ['node', 'python3', 'curl', 'yt-dlp', 'gnome-terminal-server', 'updsvc'].includes(p.name),
      eventApps: ['firefox', 'telegram-desktop', 'node', 'python3', 'slack', 'spotify', 'code', 'git', 'ssh', 'zoom', 'steam', 'apt'],
      eventHosts: [['github.com', '140.82.113.3', 443], ['pypi.org', '151.101.0.223', 443], ['api.github.com', '140.82.112.21', 443], ['zoom.us', '170.114.52.2', 443],
        ['archive.ubuntu.com', '185.125.190.36', 80], ['149.154.167.51', '149.154.167.51', 443], ['www.youtube.com', '142.250.181.238', 443], ['registry.npmjs.org', '104.16.30.34', 443]],
      destExtra: [
        ['185.199.110.133', 'objects.githubusercontent.com', 443, 'node'], ['185.125.190.36', 'archive.ubuntu.com', 80, 'http'],
        ['185.125.190.39', 'security.ubuntu.com', 80, 'http'], ['104.244.42.193', 'api.x.com', 443, 'firefox'],
        ['91.108.56.130', null, 443, 'telegram-desktop'], [LAN_GW, null, 53, 'systemd-resolved'], ['8.8.8.8', 'dns.google', 443, 'firefox'],
      ],
      allowlist: [
        { id: 5, kind: 'process', value: PY, note: 'PC Sentinel engine', ts: ago(2 * DAY) },
        { id: 4, kind: 'persistence', value: '/usr/sbin/sshd', note: 'SSH from my laptop', ts: ago(5 * DAY) },
        { id: 3, kind: 'privacy', value: ZOOM, note: 'video calls', ts: ago(5 * DAY) },
        { id: 2, kind: 'destination', value: PEER, note: 'my laptop over Tailscale (SSH)', ts: ago(6 * DAY) },
        { id: 1, kind: 'process', value: NODE, note: 'dev tool', ts: ago(9 * DAY) },
      ],
      dns: null,
      streamPool: (P) => [
        () => ({ severity: 'low', category: 'network', title: 'New destination: firefox → i.ytimg.com', summary: 'First connection from Firefox to 142.250.187.234:443.', process: ref('firefox', P.firefoxNet.pid), remote: { ip: '142.250.187.234', port: 443, host: 'i.ytimg.com' }, details: { rule: 'new_destination' } }),
        () => ({ severity: 'medium', category: 'network', title: 'New exposed listener: python3 0.0.0.0:8000', summary: 'A quick file server (python3 -m http.server) is reachable from your LAN and tailnet.', process: ref('python3', P.pip.pid), details: { rule: 'exposed_listener', ports: '8000/tcp', flags: ['exposed'] } }),
        () => ({ severity: 'low', category: 'process', title: 'First-seen process: git-remote-https', summary: 'Started by git (Ubuntu package).', process: { pid: rint(400, 250000), name: 'git-remote-https', exe: '/usr/lib/git-core/git-remote-https', signer: UBU, sig_status: 'Valid', trust: 'trusted' }, details: { rule: 'first_seen', flags: ['first_seen'] } }),
        () => ({ severity: 'low', category: 'network', title: 'New destination: python3 → download.pytorch.org', summary: 'pip connected to 18.239.94.112:443.', process: ref('python3', P.pip.pid), remote: { ip: '18.239.94.112', port: 443, host: 'download.pytorch.org' }, details: { rule: 'new_destination' } }),
      ],
    };
  }

  const PROFILE = OS === 'macos' ? macProfile() : OS === 'linux' ? linuxProfile() : windowsProfile();
  IMG = PROFILE.img;
  const PROTECTED = new Set(PROFILE.protectedNames);
  const HOST_LABEL = XSS ? `${HOST}${XP.host}` : HOST;

  /* ------------------------------------------------------------------ events (alerts + info observations) */
  function buildEvents(alerts, procs) {
    const ev = [];
    const E = (sec, severity, category, title, summary) => ev.push({ ts: ago(sec), severity, category, title, summary: summary || '' });
    alerts.forEach((a) => ev.push({ ts: a.first_ts, severity: a.severity, category: a.category, title: a.title, summary: a.summary }));
    E(ENGINE_UP, 'info', 'system', 'PC Sentinel engine started', `v1.1.0 on ${HOST} (${PROFILE.os}) as ${USER} (${FULL ? 'elevated' : 'not elevated'}).`);
    PROFILE.infoEvents(E);
    procs.filter(PROFILE.isAppStart)
      .forEach((p) => ev.push({ ts: p.started, severity: 'info', category: 'process', title: `Process started: ${p.name}`, summary: `PID ${p.pid} · parent ${p.parent || '—'} · ${p.signer ? `signed by ${p.signer}` : 'unsigned'}` }));
    // background history over three days
    for (let i = 0; i < 70; i++) {
      const sec = rint(50 * MIN, 3 * DAY - 600);
      if (rand() < 0.5) {
        E(sec, 'info', 'process', `Process started: ${pick(PROFILE.eventApps)}`, `PID ${PROFILE.platform === 'windows' ? rint(400, 9000) * 4 : rint(400, 99000)}`);
      } else {
        const [h, ip, port] = pick(PROFILE.eventHosts);
        E(sec, 'info', 'network', `New connection: ${pick(PROFILE.eventApps)} → ${h}`, `${ip}:${port}`);
      }
    }
    ev.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));
    ev.forEach((e, i) => { e.id = i + 1; });
    return ev;
  }

  function buildSettings() {
    return {
      allowlist: clone(PROFILE.allowlist),
      blocklist: [
        { id: 3, ip: '198.51.100.23', note: 'manual: phishing landing page host', ts: ago(3 * DAY) },
        { id: 2, ip: '203.0.113.45', note: 'manual: RDP brute force seen in router log', ts: ago(7 * DAY) },
        { id: 1, ip: C2, note: 'example C2 (demo data)', ts: ago(9 * DAY) },
      ],
      notify: { enabled: false, min_severity: 'high' },
      autostart: Object.assign({}, PROFILE.autostart),
    };
  }

  /* ------------------------------------------------------------------ live map graph */
  /** Mirrors GET /api/graph: process nodes grouped per exe, remote nodes per IP, host/net/spawn edges.
      Only processes with a remote (non-loopback) connection or a listening port get a host edge;
      their parents are added as context nodes for spawn edges. */
  function graph() {
    const conns = liveConns().filter((c) => c.raddr && !/^127\.|^::1$/.test(c.raddr));
    const bl = new Set(db.settings.blocklist.map((b) => b.ip));
    const byPid = {};
    db.procs.forEach((p) => { byPid[p.pid] = p; });
    const keyOf = (exe, name) => `p:${String(exe || name || '').toLowerCase()}`;
    const groups = {};
    const group = (p) => {
      const id = keyOf(p.exe, p.name);
      const g = groups[id] || (groups[id] = {
        id, type: 'process', label: p.name, exe: p.exe || null, pids: [], trust: p.trust, signer: p.signer, sig_status: p.sig_status,
        conns: 0, cpu: 0, mem_mb: 0, flags: [], parent: p.parent || null, _net: false,
      });
      return g;
    };
    // aggregate every process into its exe group (cpu/mem/pids), then mark the networked ones
    const procs = processes('all').items;
    procs.forEach((p) => {
      const g = group(p);
      g.pids.push(p.pid);
      g.cpu += p.cpu;
      g.mem_mb += p.mem_mb;
      p.flags.forEach((f) => { if (!g.flags.includes(f)) g.flags.push(f); });
    });
    const netEdges = {};
    const remotes = {};
    conns.forEach((c) => {
      const p = byPid[c.pid] || { pid: c.pid, name: c.process, exe: c.exe, trust: c.trust, signer: c.signer, sig_status: 'Unknown' };
      const g = group(p);
      g.conns++;
      g._net = true;
      c.flags.forEach((f) => { if (!g.flags.includes(f)) g.flags.push(f); });
      const rid = `r:${c.raddr}`;
      const r = remotes[rid] || (remotes[rid] = { id: rid, type: 'remote', label: c.rhost || c.raddr, ip: c.raddr, host: c.rhost || null, ports: [], blocklisted: bl.has(c.raddr), private: isPrivate(c.raddr) });
      if (!r.ports.includes(c.rport)) r.ports.push(c.rport);
      const ek = `${g.id}|${rid}|${c.direction}`;
      const e = netEdges[ek] || (netEdges[ek] = { source: g.id, target: rid, kind: 'net', count: 0, ports: [], direction: c.direction, states: [], danger: false });
      e.count++;
      if (!e.ports.includes(c.rport)) e.ports.push(c.rport);
      if (!e.states.includes(c.status)) e.states.push(c.status);
      e.danger = e.danger || r.blocklisted || ['malicious', 'suspicious'].includes(g.trust);
    });
    db.listening.forEach((l) => { // like the engine: only listeners bound to all interfaces put a process on the map
      const p = byPid[l.pid];
      if (p && l.exposed) group(p)._net = true;
    });
    const nodes = [{ id: 'host', type: 'host', label: HOST_LABEL }];
    const edges = [];
    const included = new Set();
    Object.values(groups).filter((g) => g._net).forEach((g) => {
      included.add(g.id);
      edges.push({ source: 'host', target: g.id, kind: 'host' });
    });
    // parents of networked processes (context nodes) + spawn edges
    const spawn = new Set();
    procs.forEach((p) => {
      const cid = keyOf(p.exe, p.name);
      if (!groups[cid] || !groups[cid]._net) return;
      const parent = byPid[p.ppid];
      if (!parent) return;
      const pid = keyOf(parent.exe, parent.name);
      if (pid === cid || spawn.has(`${pid}|${cid}`)) return;
      spawn.add(`${pid}|${cid}`);
      if (!included.has(pid)) {
        included.add(pid);
        edges.push({ source: 'host', target: pid, kind: 'host' }); // the engine links every process node to the host
      }
      edges.push({ source: pid, target: cid, kind: 'spawn' });
    });
    included.forEach((id) => {
      const g = groups[id];
      const out = strip(g);
      out.cpu = Math.round(g.cpu * 10) / 10;
      out.mem_mb = Math.round(g.mem_mb);
      nodes.push(out);
    });
    Object.values(remotes).forEach((r) => {
      r.ports.sort((a, b) => a - b);
      nodes.push(r);
    });
    Object.values(netEdges).forEach((e) => edges.push(e));
    return { generated: nowIso(), nodes, edges };
  }

  /* ------------------------------------------------------------------ throughput (bytes per second) */
  function sampleAt(t) {
    const m = (T0 - t) / 60000; // minutes before page load; negative = live
    const w = (a, b, ramp) => smooth((m - a) / ramp) * smooth((b - m) / ramp);
    let rx = 70e3 + 35e3 * Math.sin(t / 97000) + 18e3 * Math.sin(t / 23000) + rnd(-1, 1) * 22e3;
    let tx = 16e3 + 6e3 * Math.sin(t / 61000) + rnd(-1, 1) * 5e3;
    const call = smooth((34 - m) / 0.6); // video call for the last 34 minutes
    rx += call * (260e3 + rnd(-1, 1) * 45e3);
    tx += call * (150e3 + rnd(-1, 1) * 30e3);
    rx += w(45, 52.5, 0.6) * (2.6e6 + rnd(-1, 1) * 380e3); // pip download
    tx += w(14, 24, 0.5) * (420e3 + rnd(-1, 1) * 130e3); // SSH session from the laptop
    if (rand() < 0.035) rx += rnd(250e3, 700e3); // page loads
    const cpu = 7 + 3 * Math.sin(t / 130000) + call * 4 + w(45, 52.5, 0.6) * 9 + w(14, 24, 0.5) * 6 + rnd(-1, 1) * 1.8 + (rand() < 0.04 ? rnd(8, 20) : 0);
    return { rx_bps: Math.max(1200, Math.round(rx)), tx_bps: Math.max(600, Math.round(tx)), cpu: Math.round(Math.max(1, cpu) * 10) / 10 };
  }

  /* ------------------------------------------------------------------ database */
  let db = null;
  function ensure() {
    if (db) return db;
    const { procs, P } = PROFILE.buildProcesses();
    const alerts = PROFILE.buildAlerts(P);
    db = {
      procs, P,
      conns: PROFILE.buildConnections(P),
      pool: PROFILE.buildPool(P).map(([proc, ip, port, host, proto]) => ({ conn: mkConn(proc, ip, port, host, { proto, age: rint(5, 400) }), on: rand() < 0.5 })),
      listening: PROFILE.buildListening(P),
      alerts,
      events: buildEvents(alerts, procs),
      privacy: PROFILE.buildPrivacy(P),
      persistence: PROFILE.buildPersistence(),
      files: PROFILE.buildFiles(P),
      settings: buildSettings(),
      metrics: [],
      destHist: {},
      nextAlertId: 49,
      nextEventId: 0,
      streamPool: 0,
      stream: PROFILE.streamPool(P),
      killed: new Set(),
    };
    db.nextEventId = db.events.length + 1;
    const end = Math.floor(T0 / 5000) * 5000;
    for (let t = end - 60 * 60000; t <= end; t += 5000) {
      const s = sampleAt(t);
      db.metrics.push(Object.assign({ t: iso(t), _ms: t, conns: 0 }, s));
    }
    const base = db.conns.length + 4;
    db.metrics.forEach((p) => { p.conns = base + Math.round(rnd(-4, 5)); });
    seedDestinations();
    if (XSS) injectXss();
    return db;
  }

  let lastChurn = 0;
  function liveConns() {
    if (Date.now() - lastChurn > 2500) {
      lastChurn = Date.now();
      db.pool.forEach((x) => { if (rand() < 0.18) x.on = !x.on; });
    }
    return db.conns.concat(db.pool.filter((x) => x.on && !db.killed.has(x.conn.pid)).map((x) => x.conn));
  }

  function seedDestinations() {
    const add = (ip, host, port, app, hits, firstSec, lastSec) => {
      const d = db.destHist[ip] || (db.destHist[ip] = { ip, host: host || null, ports: [], apps: [], hits: 0, first_seen: ago(firstSec), last_seen: ago(lastSec) });
      if (!d.ports.includes(port)) d.ports.push(port);
      if (!d.apps.includes(app)) d.apps.push(app);
      d.hits += hits;
    };
    db.conns.concat(db.pool.map((x) => x.conn)).forEach((c) => {
      const first = Math.max(60, Math.round((T0 - new Date(c.first_seen).getTime()) / 1000) + rint(0, 4 * HOUR));
      add(c.raddr, c.rhost, c.rport, c.process, c.raddr === C2 ? 14 : rint(1, 160), Math.min(first, 23 * HOUR), rint(5, 300));
    });
    PROFILE.destExtra.forEach(([ip, host, port, app]) => add(ip, host, port, app, rint(1, 60), rint(4 * HOUR, 23 * HOUR), rint(20 * MIN, 3 * HOUR)));
  }

  /* ------------------------------------------------------------------ derived views */
  const isPrivate = (ip) => /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(String(ip)) || ip === '::1';
  const exposedCount = () => new Set(db.listening.filter((l) => l.exposed).map((l) => `${l.lport}/${l.proto}`)).size;

  function openCounts() {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    db.alerts.forEach((a) => { if (a.status === 'open' && Object.prototype.hasOwnProperty.call(c, a.severity)) c[a.severity]++; });
    return c;
  }
  function risk(c) {
    const s = Math.min(100, c.critical * 30 + c.high * 12 + c.medium * 4 + c.low);
    const label = s < 10 ? 'Low' : s < 25 ? 'Guarded' : s < 50 ? 'Elevated' : s < 75 ? 'High' : 'Severe';
    return { score: s, label };
  }
  const devInUse = (k) => !!(db.privacy.devices && db.privacy.devices[k] && db.privacy.devices[k].in_use);
  function summary() {
    ensure();
    const conns = liveConns();
    const last = db.metrics[db.metrics.length - 1];
    const counts = openCounts();
    const out = {
      engine: {
        version: '1.1.0', started: ago(ENGINE_UP), uptime_s: Math.round((Date.now() - (T0 - ENGINE_UP * 1000)) / 1000),
        host: HOST_LABEL, user: USER, elevated: FULL, platform: PROFILE.platform, os: PROFILE.os,
      },
      coverage: PROFILE.coverage(),
      coverage_supported: Object.assign({}, PROFILE.supported),
      defender: PROFILE.defender(),
      kpis: {
        alerts_open: counts,
        processes: db.procs.length, connections: conns.length, listening_exposed: exposedCount(),
        remote_hosts_24h: Object.keys(db.destHist).length, apps_online: new Set(conns.map((c) => c.exe || c.process)).size,
        camera_in_use: devInUse('webcam'), mic_in_use: devInUse('microphone'),
      },
      throughput: { rx_bps: last.rx_bps, tx_bps: last.tx_bps },
      risk: risk(counts),
    };
    if (XSS) {
      out.engine.version = `1.1.0${XP.host}`;
      out.engine.os = `${PROFILE.os} ${XP.img}`;
      out.engine.user = `${USER}${XP.single}`;
      out.coverage.canaries = `3${XP.host}`;
      out.kpis.apps_online = XP.img;
      if (out.defender) Object.assign(out.defender, { signatures: XP.img, signatures_age_h: `30${XP.host}` });
    }
    return out;
  }
  const strip = (o) => {
    const out = {};
    Object.keys(o).forEach((k) => { if (k[0] !== '_') out[k] = o[k]; });
    return out;
  };

  function processes(filter) {
    const conns = liveConns();
    const n = {};
    conns.forEach((c) => { n[c.pid] = (n[c.pid] || 0) + 1; });
    let list = db.procs.map((p) => {
      const jitter = 0.5 * (p._cpu * (0.55 + rand() * 0.9) + (rand() < 0.02 ? rnd(0.5, 3) : 0));
      return Object.assign(strip(p), { cpu: Math.round(jitter * 10) / 10, net_conns: n[p.pid] || 0, mem_mb: Math.round(p.mem_mb * (0.98 + rand() * 0.04) * 10) / 10 });
    });
    if (filter === 'flagged') list = list.filter((p) => (p.flags.length && !(p.flags.length === 1 && p.flags[0] === 'unsigned')) || ['malicious', 'suspicious'].includes(p.trust));
    if (filter === 'unsigned') list = list.filter((p) => ['unsigned', 'suspicious', 'malicious'].includes(p.trust));
    const order = { malicious: 0, suspicious: 1, unsigned: 2, known: 3, trusted: 4 };
    const rank = (t) => (Object.prototype.hasOwnProperty.call(order, t) ? order[t] : 5);
    list.sort((a, b) => (rank(a.trust) - rank(b.trust)) || (b.cpu - a.cpu));
    return { items: list };
  }

  function apps() {
    const conns = liveConns();
    const map = {};
    conns.forEach((c) => {
      const k = String(c.exe || c.process).toLowerCase();
      const a = map[k] || (map[k] = { process: c.process, exe: c.exe, signer: c.signer, trust: c.trust, conns: 0, _h: new Set(), _p: new Set(), _f: new Set(), first: c.first_seen });
      a.conns++;
      a._h.add(c.raddr);
      a._p.add(c.rport);
      c.flags.forEach((f) => a._f.add(f));
      if (c.first_seen < a.first) a.first = c.first_seen;
    });
    const items = Object.values(map).map((a) => ({
      process: a.process, exe: a.exe, signer: a.signer, trust: a.trust, conns: a.conns, remote_hosts: a._h.size,
      ports: Array.from(a._p).sort((x, y) => x - y).slice(0, 20), first_seen: a.first, last_seen: nowIso(), flags: Array.from(a._f).sort(),
    }));
    items.sort((a, b) => b.conns - a.conns);
    return { items };
  }

  function destinations() {
    const bl = new Set(db.settings.blocklist.map((b) => b.ip));
    const live = new Set(liveConns().map((c) => c.raddr));
    const items = Object.values(db.destHist).map((d) => Object.assign(clone(d), {
      last_seen: live.has(d.ip) ? nowIso() : d.last_seen, blocklisted: bl.has(d.ip), private: isPrivate(d.ip),
    }));
    items.sort((a, b) => (a.last_seen < b.last_seen ? 1 : -1));
    return { items };
  }

  function alertsQuery(q) {
    const status = q.get('status') || 'open';
    const sev = (q.get('severity') || '').split(',').filter(Boolean);
    const cat = q.get('category') || '';
    const text = (q.get('q') || '').toLowerCase();
    const limit = Number(q.get('limit') || 200);
    const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const r = (s) => (Object.prototype.hasOwnProperty.call(rank, s) ? rank[s] : 5);
    let list = db.alerts.filter((a) => (status === 'all' || a.status === status) && (!sev.length || sev.includes(a.severity)) && (!cat || a.category === cat));
    if (text) list = list.filter((a) => JSON.stringify([a.title, a.summary, a.process, a.remote]).toLowerCase().includes(text));
    list.sort((a, b) => (r(a.severity) - r(b.severity)) || (a.last_ts < b.last_ts ? 1 : -1));
    return { items: clone(list.slice(0, limit)) };
  }

  function dnsList() {
    if (!PROFILE.dns || (!FULL && !XSS)) return { enabled: false, items: [] };
    const items = [];
    for (let i = 0; i < 60; i++) {
      const [proc, name, type, result] = PROFILE.dns[i % PROFILE.dns.length];
      items.push({ ts: ago(i * 41 + rint(0, 30)), pid: proc === 'updsvc.exe' ? MAL_PID : rint(400, 9000) * 4, process: proc, query: name, type, result });
    }
    if (XSS) items.unshift({ ts: ago(5), pid: `31337${XP.host}`, process: XP.img, query: `${XP.host}.example.net`, type: '<b>A</b>', result: XP.img });
    return { enabled: true, items };
  }

  function addEvent(a) {
    db.events.push({ id: db.nextEventId++, ts: a.last_ts, severity: a.severity, category: a.category, title: a.title, summary: a.summary });
  }

  /* ------------------------------------------------------------------ XSS self-test data (&xss=1 only) */
  function injectXss() {
    const exe = PROFILE.platform === 'windows' ? `C:\\Users\\alex\\AppData\\Local\\Temp\\${XP.host}\\${XP.img}.exe` : `/tmp/${XP.host}/${XP.img}`;
    const parent = db.procs[0];
    const xp = {
      pid: 31337, ppid: parent.pid, parent: '<svg/onload=alert(1)>', name: XP.img, exe,
      cmdline: `"${exe}" --title=${XP.script} --x='${XP.host}' ${XP.single}`, user: '<i>root</i>', started: ago(120),
      signer: '<b>Evil</b> & Co "Ltd" \'x\'', sig_status: XP.script, trust: XP.attr, cpu: 0, mem_mb: 5, net_conns: 0,
      flags: [XP.host, 'constructor', '__proto__', 'toString', XP.img], _cpu: 0.4,
    };
    db.procs.push(xp);
    const xconn = {
      pid: 31337, process: XP.img, exe, signer: xp.signer, trust: xp.trust, proto: 'TCP<b>', laddr: LAN_IP, lport: 51111,
      raddr: '203.0.113.99', rport: 443, rhost: XP.host, status: '<b>ESTABLISHED</b>', direction: `in${XP.host}`, first_seen: ago(60), flags: [XP.host],
    };
    db.conns.push(xconn);
    db.listening.push({ proto: XP.img, laddr: '0.0.0.0', lport: `8080${XP.host}`, pid: 31337, process: XP.img, exe, trust: xp.trust, exposed: true, first_seen: ago(60) });
    db.destHist['203.0.113.99'] = { ip: '203.0.113.99', host: XP.host, ports: [443, XP.img], apps: [XP.img, 'constructor'], hits: `7${XP.host}`, first_seen: ago(600), last_seen: ago(5) };
    db.alerts.push(
      { id: 900, ts: ago(30), first_ts: ago(300), last_ts: ago(30), count: 3, severity: 'critical', category: 'network',
        title: `${XP.img} connected to ${XP.host}`, summary: `${XP.script} & "quotes" 'single' ${XP.single}`,
        process: { pid: 31337, name: XP.img, exe, signer: xp.signer, sig_status: 'HashMismatch', trust: xp.trust },
        remote: { ip: '203.0.113.99', port: 443, host: XP.host },
        details: { rule: '<b>rule</b>', [XP.img]: 'key is a payload', cmdline: xp.cmdline, path: exe, nested: { a: '<svg onload=alert(1)>' }, list: ['<b>x</b>', 1], when: ago(60), flags: [XP.host] },
        status: 'open' },
      { id: 901, ts: ago(40), first_ts: ago(40), last_ts: ago(40), count: `2${XP.host}`, severity: `high${XP.host}`, category: 'constructor',
        title: 'Hostile enum values (severity, category, count)', summary: XP.img, process: null, remote: null, details: {}, status: 'open' },
      { id: 902, ts: ago(50), first_ts: ago(50), last_ts: ago(50), count: 1, severity: 'low', category: '__proto__',
        title: 'Hostile status value', summary: XP.host, process: null, remote: null, details: {}, status: `open${XP.host}` },
    );
    db.events.push({ id: 99999, ts: nowIso(), severity: 'info', category: '__proto__', title: XP.img, summary: XP.host });
    if (db.privacy.devices && db.privacy.devices.microphone) db.privacy.devices.microphone.by.push(XP.img);
    db.privacy.history.push({ device: XP.host, app: XP.img, path: exe, start: ago(600), stop: ago(500), in_use: false, trust: xp.trust, allowed: false });
    const pkind = PROFILE.platform === 'windows' ? 'scheduled_task' : PROFILE.platform === 'macos' ? 'launch_agent' : 'systemd_unit';
    db.persistence.push(
      mkPersist(pkind, `\\${XP.host}\\`, XP.img, `"${exe}" ${XP.script}`, exe, xp.signer, 'NotSigned', xp.trust, 'new', 120, [XP.host]),
      mkPersist('<b>kind</b>', XP.host, `${XP.single}name`, XP.img, exe, null, XP.img, 'suspicious', `new${XP.host}`, 120, []),
    );
    db.files.watched.push({ path: exe, label: XP.img, kind: '<b>kind</b>', audited: true, exists: true });
    db.files.access.push({ ts: ago(90), path: exe, label: XP.host, kind: XP.img, process: XP.img, pid: `31337${XP.host}`, exe, access: '<i>ReadData</i>', expected: false });
    db.settings.allowlist.unshift({ id: 77, kind: '<b>kind</b>', value: exe, note: XP.img, ts: ago(60) });
    db.settings.blocklist.unshift({ id: 78, ip: '203.0.113.99', note: XP.host, ts: ago(60) });
    db.settings.autostart.detail = `${XP.img} ${PROFILE.autostart.detail}`;
  }

  /* ------------------------------------------------------------------ request router */
  function err(status, message) {
    const e = new Error(message);
    e.status = status;
    return e;
  }

  async function request(method, path, body) {
    await sleep(rnd(40, 170));
    if (offline) throw new TypeError('Failed to fetch (mock engine offline)');
    ensure();
    const url = new URL(path, 'http://mock.local');
    const p = url.pathname;
    const q = url.searchParams;
    body = body || {};

    if (method === 'GET') {
      switch (p) {
        case '/api/summary': return summary();
        case '/api/metrics': {
          const since = Date.now() - Number(q.get('minutes') || 60) * 60000;
          return { points: db.metrics.filter((m) => m._ms >= since).map(strip) };
        }
        case '/api/alerts': return alertsQuery(q);
        case '/api/network/connections': return { items: clone(liveConns()) };
        case '/api/network/apps': return apps();
        case '/api/network/destinations': return destinations();
        case '/api/network/listening': {
          const items = clone(db.listening).sort((a, b) => (a.exposed === b.exposed ? a.lport - b.lport : a.exposed ? -1 : 1));
          return { items };
        }
        case '/api/dns': return dnsList();
        case '/api/processes': return processes(q.get('filter') || 'all');
        case '/api/privacy': return clone(db.privacy);
        case '/api/persistence': return { items: clone(db.persistence) };
        case '/api/files': return Object.assign({ audit_enabled: FILE_AUDIT && PROFILE.supported.file_audit }, clone(db.files));
        case '/api/events': {
          const cat = q.get('category') || '';
          const limit = Number(q.get('limit') || 300);
          const items = db.events.filter((e) => !cat || e.category === cat).slice().sort((a, b) => b.id - a.id).slice(0, limit);
          return { items: clone(items) };
        }
        case '/api/settings': return clone(db.settings);
        case '/api/graph': return graph();
        default: throw err(404, 'Not found');
      }
    }

    // POST
    const ackMatch = p.match(/^\/api\/alerts\/(\d+)\/ack$/);
    if (ackMatch) {
      const a = db.alerts.find((x) => x.id === Number(ackMatch[1]));
      if (a && a.status === 'open') a.status = 'acknowledged';
      return { ok: true };
    }
    if (p === '/api/alerts/ack_all') {
      let n = 0;
      db.alerts.forEach((a) => {
        if (a.status === 'open' && (!body.severity || a.severity === body.severity)) { a.status = 'acknowledged'; n++; }
      });
      return { ok: true, count: n };
    }
    switch (p) {
      case '/api/actions/kill': {
        const proc = db.procs.find((x) => x.pid === Number(body.pid));
        if (!proc) return { ok: false, message: `Process ${body.pid} is not running.` };
        if (PROTECTED.has(proc.name)) return { ok: false, message: `${proc.name} is a core ${PROFILE.osWord} process and is protected from being killed here.` };
        db.procs = db.procs.filter((x) => x.pid !== proc.pid);
        db.conns = db.conns.filter((c) => c.pid !== proc.pid);
        db.listening = db.listening.filter((l) => l.pid !== proc.pid);
        db.killed.add(proc.pid);
        return { ok: true, message: `Killed ${proc.name} (PID ${proc.pid}).` };
      }
      case '/api/actions/block_ip': {
        const ip = String(body.ip || '').trim();
        if (!/^[0-9a-f:.]+$/i.test(ip)) return { ok: false, message: `'${ip}' is not a valid IP address.` };
        if (isPrivate(ip)) return { ok: false, message: `${ip} is a local/private address; refusing to block it.` };
        if (!db.settings.blocklist.some((b) => b.ip === ip)) {
          db.settings.blocklist.unshift({ id: Math.max(0, ...db.settings.blocklist.map((b) => b.id)) + 1, ip, note: body.note || 'Blocked from dashboard', ts: nowIso() });
        }
        return { ok: true, message: PROFILE.blockMessage(ip) };
      }
      case '/api/actions/allow': {
        const kinds = ['process', 'destination', 'privacy', 'persistence'];
        if (!kinds.includes(body.kind) || !body.value) return { ok: false, message: 'Invalid allowlist entry.' };
        const v = String(body.value).toLowerCase();
        if (!db.settings.allowlist.some((x) => x.kind === body.kind && String(x.value).toLowerCase() === v)) {
          db.settings.allowlist.unshift({ id: Math.max(0, ...db.settings.allowlist.map((x) => x.id)) + 1, kind: body.kind, value: body.value, note: body.note || '', ts: nowIso() });
        }
        let n = 0;
        db.alerts.forEach((a) => {
          if (a.status !== 'open') return;
          const hit = body.kind === 'destination' ? a.remote && a.remote.ip === body.value : a.process && String(a.process.exe || '').toLowerCase() === v;
          if (hit) { a.status = 'allowed'; n++; }
        });
        db.privacy.history.forEach((h) => { if (body.kind === 'privacy' && String(h.path).toLowerCase() === v) h.allowed = true; });
        return { ok: true, message: `Allowed ${body.value} (${body.kind}); ${n} matching alert(s) closed.` };
      }
      case '/api/actions/blocklist': {
        const ip = String(body.ip || '').trim();
        if (!/^[0-9a-f:.]+$/i.test(ip) || ip.length < 2) return { ok: false, message: `'${ip}' is not a valid IP address.` };
        if (!db.settings.blocklist.some((b) => b.ip === ip)) {
          db.settings.blocklist.unshift({ id: Math.max(0, ...db.settings.blocklist.map((b) => b.id)) + 1, ip, note: body.note || '', ts: nowIso() });
        }
        return { ok: true, message: `${ip} added to the blocklist.` };
      }
      case '/api/actions/unblocklist':
        db.settings.blocklist = db.settings.blocklist.filter((b) => b.id !== Number(body.id));
        return { ok: true, message: 'Removed from the blocklist.' };
      case '/api/actions/unallow':
        db.settings.allowlist = db.settings.allowlist.filter((x) => x.id !== Number(body.id));
        return { ok: true, message: 'Removed from the allowlist.' };
      case '/api/actions/notify': {
        const levels = ['critical', 'high', 'medium', 'low'];
        const min = body.min_severity || db.settings.notify.min_severity;
        if (!levels.includes(min)) return { ok: false, message: 'Invalid level.' };
        db.settings.notify = { enabled: !!body.enabled, min_severity: min };
        return { ok: true, message: body.enabled ? `Desktop pop-ups on for ${min} and above.` : 'Desktop pop-ups off.' };
      }
      case '/api/actions/autostart': {
        const a = db.settings.autostart;
        if (!a.supported) return { ok: false, message: `Start at login is not available on ${PROFILE.osWord}.` };
        a.enabled = !!body.enabled;
        return { ok: true, message: a.enabled ? `PC Sentinel starts at login (${PROFILE.autostart.detail}).` : 'PC Sentinel no longer starts at login.' };
      }
      default:
        return { ok: false, message: 'unknown action' };
    }
  }

  /* ------------------------------------------------------------------ fake SSE stream */
  function pushMetric() {
    const t = Date.now();
    const s = sampleAt(t);
    const p = Object.assign({ t: iso(t), _ms: t, conns: db.conns.length + 4 + Math.round(rnd(-3, 4)) }, s);
    db.metrics.push(p);
    const cutoff = t - 2 * HOUR * 1000;
    while (db.metrics.length && db.metrics[0]._ms < cutoff) db.metrics.shift();
    return strip(p);
  }

  function streamAlert() {
    const pool = db.stream;
    const crit = db.alerts.find((a) => a.id === 46);
    const malExe = String((IMG[db.P.mal.name] || [''])[0]).toLowerCase();
    const canRepeat = crit && !db.killed.has(MAL_PID) && !db.settings.allowlist.some((x) => String(x.value).toLowerCase() === malExe);
    if (db.streamPool < pool.length && (rand() < 0.6 || !canRepeat)) {
      const make = pool[db.streamPool++];
      const a = make();
      if (!a || (a.process && a.process.pid === MAL_PID && db.killed.has(MAL_PID))) return null;
      const full = Object.assign({ id: db.nextAlertId++, ts: nowIso(), first_ts: nowIso(), last_ts: nowIso(), count: 1, remote: null, status: 'open' }, a);
      db.alerts.push(full);
      addEvent(full);
      return clone(full);
    }
    if (canRepeat) {
      crit.count += 1;
      crit.last_ts = nowIso();
      crit.ts = crit.last_ts; // like the engine: repeats bump the count but never re-open an acknowledged alert
      return clone(crit);
    }
    return null;
  }

  let offline = false;
  class MockStream {
    constructor() {
      ensure();
      this.readyState = 0;
      this.onopen = null;
      this.onerror = null;
      this.handlers = {};
      this.timers = [];
      this.timers.push(setTimeout(() => this.open(), 250));
      this.timers.push(setInterval(() => this.tick(), 2000));
      this.timers.push(setInterval(() => this.emit('summary', summary()), 10000));
      this.scheduleAlert();
    }
    addEventListener(type, fn) { (this.handlers[type] = this.handlers[type] || []).push(fn); }
    removeEventListener(type, fn) { this.handlers[type] = (this.handlers[type] || []).filter((f) => f !== fn); }
    open() {
      if (offline || this.readyState === 2) return;
      this.readyState = 1;
      if (this.onopen) this.onopen({ type: 'open' });
      this.emit('summary', summary());
    }
    emit(type, obj) {
      if (this.readyState !== 1 || offline) return;
      const ev = { type, data: JSON.stringify(obj) };
      (this.handlers[type] || []).forEach((fn) => fn(ev));
    }
    tick() {
      if (offline) {
        if (this.readyState === 1) {
          this.readyState = 0;
          if (this.onerror) this.onerror({ type: 'error' });
        }
        return;
      }
      if (this.readyState === 0) this.open();
      this.emit('metric', pushMetric());
    }
    scheduleAlert() {
      clearTimeout(this.alertTimer);
      this.alertTimer = setTimeout(() => {
        if (this.readyState === 1 && !offline) {
          const a = streamAlert();
          if (a) this.emit('alert', a);
        }
        if (this.readyState !== 2) this.scheduleAlert();
      }, rnd(15000, 32000));
    }
    close() {
      this.readyState = 2;
      clearTimeout(this.alertTimer);
      this.timers.forEach((t) => { clearTimeout(t); clearInterval(t); });
    }
  }

  PCS.mock = {
    os: OS,
    setup: SETUP,
    xss: XSS,
    request,
    stream: () => new MockStream(),
    setOffline(v) { offline = !!v; return `mock engine ${offline ? 'offline' : 'online'}`; },
  };

  /* ------------------------------------------------------------------ XSS self-test (&xss=1 only)
     Open ?mock=1&xss=1 (optionally &os=macos|linux), then run `await PCS.xssSelfTest()` in the console.
     Every payload uses alert(); alert() is replaced by a recorder so a hit is counted instead of blocking the page.
     PASS = no payload executed, no element was injected, and the payload text is visible as literal text. */
  if (XSS) {
    window.__pcsXssFired = [];
    window.alert = function (m) {
      window.__pcsXssFired.push(String(m));
      console.error('[xss self-test] a payload EXECUTED:', m);
    };
    const MARKERS = [XP.img, XP.host];
    // waits via MessageChannel instead of chained setTimeout, which browsers throttle hard in hidden/background tabs
    const wait = (msTime) => new Promise((resolve) => {
      const end = performance.now() + msTime;
      const ch = new MessageChannel();
      ch.port1.onmessage = () => {
        if (performance.now() >= end) { ch.port1.close(); resolve(); } else ch.port2.postMessage(0);
      };
      ch.port2.postMessage(0);
    });
    // the app itself only creates <svg> icons/charts with these classes and no <img>, <script> without src, or on* attributes
    const injected = () => {
      const bad = Array.from(document.querySelectorAll('img, iframe, object, embed, script:not([src]), [onerror], [onload], [onmouseover], [onfocus], [onclick]'));
      const svgs = Array.from(document.querySelectorAll('svg')).filter((s) => !s.matches('.ic, .logo, .spark, .donut, .gauge-svg'));
      return bad.concat(svgs);
    };
    const literal = (el) => !!el && MARKERS.some((m) => el.textContent.includes(m));
    PCS.xssSelfTest = async function () {
      const rows = [];
      window.__pcsXssRows = rows; // live progress, readable while the test runs
      const check = (where, el) => {
        const hits = injected();
        rows.push({ where, injectedElements: hits.length, payloadShownAsText: literal(el) });
        if (hits.length) console.warn(`[xss self-test] injected element(s) in ${where}:`, hits);
      };
      const routes = ['map', 'overview', 'alerts', 'network/connections', 'network/apps', 'network/destinations', 'network/listening', 'network/dns',
        'processes', 'privacy', 'persistence', 'files', 'timeline', 'settings'];
      for (const r of routes) {
        location.hash = `#/${r}`;
        await wait(1100);
        if (r === 'alerts') {
          const sel = document.querySelector('#view [data-status="all"]');
          if (sel) { sel.click(); await wait(900); }
        }
        if (r === 'processes') {
          const btn = Array.from(document.querySelectorAll('[data-expand]')).find((b) => b.dataset.expand === '31337');
          if (btn) { btn.click(); await wait(300); }
        }
        check(`view: ${r}`, document.getElementById('view'));
      }
      check('sidebar engine card', document.getElementById('sidebar-foot'));
      // alert drawer for the hostile alert
      PCS.openAlert(900);
      await wait(400);
      check('alert drawer', document.getElementById('drawer'));
      PCS.ui.drawer.close();
      // map: tooltips + drawers for the host node, the hostile process node and the hostile remote node
      location.hash = '#/map';
      await wait(1600);
      const mv = PCS.views.map;
      const nodes = (mv.raw && mv.raw.nodes) || [];
      const targets = [nodes.find((n) => n.type === 'host'), nodes.find((n) => n.type === 'process' && n.label === XP.img), nodes.find((n) => n.type === 'remote' && n.host === XP.host)];
      for (const n of targets.filter(Boolean)) {
        mv.graph.showTip({ d: n }, { x: 40, y: 40 });
        check(`map tooltip: ${n.type}`, mv.graph.tip);
        mv.graph.hideTip();
        mv.select(n);
        await wait(300);
        check(`map drawer: ${n.type}`, document.getElementById('drawer'));
        PCS.ui.drawer.close();
        await wait(300);
      }
      // the kill confirmation dialog quotes the process name and path
      const dlgDone = PCS.actions.kill({ pid: 31337, name: XP.img, exe: `/tmp/${XP.host}` });
      await wait(200);
      check('kill dialog', document.getElementById('dialog'));
      const cancel = document.querySelector('#dialog [data-dlg-cancel]');
      if (cancel) cancel.click(); else document.getElementById('dialog').close();
      await dlgDone;
      location.hash = '#/overview';
      const fired = window.__pcsXssFired.slice();
      const ok = !fired.length && rows.every((r) => r.injectedElements === 0);
      console.table(rows);
      console.log(`%c[xss self-test] ${ok ? 'PASS' : 'FAIL'}: ${fired.length} payload(s) executed, ${rows.reduce((a, r) => a + r.injectedElements, 0)} injected element(s) across ${rows.length} checks.`,
        `font-weight:bold;color:${ok ? '#2dd4bf' : '#ef4444'}`);
      return { ok, fired, rows };
    };
  }
})();
