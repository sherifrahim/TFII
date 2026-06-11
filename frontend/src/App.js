import { useState, useEffect, useCallback, useRef } from "react";

const API_BASE = "https://YOUR_DOMAIN";
const INDUSTRIES = ["Fintech","Medical","Gaming","Retail","Energy","Government","Telecom"];
const IOC_TYPES  = ["IPv4","IPv6","Domain","URL","MD5","SHA1","SHA256","Email","CVE"];
const TLP_LEVELS = ["WHITE","GREEN","AMBER","RED"];
const REL_TYPES  = ["related_to","resolves_to","dropped_by","communicates_with","variant_of","delivers","uses"];
const MITRE_TECHNIQUES = [
  "T1566 - Phishing","T1566.001 - Spearphishing Attachment","T1566.002 - Spearphishing Link",
  "T1071 - Application Layer Protocol","T1071.001 - Web Protocols","T1071.004 - DNS",
  "T1190 - Exploit Public-Facing Application","T1059 - Command and Scripting Interpreter",
  "T1078 - Valid Accounts","T1133 - External Remote Services","T1486 - Data Encrypted for Impact",
  "T1041 - Exfiltration Over C2 Channel","T1055 - Process Injection","T1003 - OS Credential Dumping",
  "T1110 - Brute Force","T1562 - Impair Defenses","T1027 - Obfuscated Files or Information",
  "T1105 - Ingress Tool Transfer","T1021 - Remote Services","T1140 - Deobfuscate/Decode Files",
];
const TLP_COLORS = {
  WHITE:{color:"#9ca3af",bg:"#9ca3af15"},GREEN:{color:"#16a34a",bg:"#16a34a15"},
  AMBER:{color:"#d97706",bg:"#d9770615"},RED:{color:"#dc2626",bg:"#dc262615"},
};
const COUNTRY_NAMES = {
  US:"United States",CN:"China",RU:"Russia",DE:"Germany",GB:"United Kingdom",
  FR:"France",NL:"Netherlands",UA:"Ukraine",BR:"Brazil",IN:"India",
  KR:"South Korea",JP:"Japan",CA:"Canada",AU:"Australia",IT:"Italy",
  RO:"Romania",TR:"Turkey",IR:"Iran",KP:"North Korea",SG:"Singapore",
};
const COUNTRY_FLAGS = {
  US:"🇺🇸",CN:"🇨🇳",RU:"🇷🇺",DE:"🇩🇪",GB:"🇬🇧",FR:"🇫🇷",NL:"🇳🇱",UA:"🇺🇦",
  BR:"🇧🇷",IN:"🇮🇳",KR:"🇰🇷",JP:"🇯🇵",CA:"🇨🇦",AU:"🇦🇺",IT:"🇮🇹",
  RO:"🇷🇴",TR:"🇹🇷",IR:"🇮🇷",KP:"🇰🇵",SG:"🇸🇬",
};

const THEMES = {
  // Professional light — matches screenshot 1
  light:{
    name:"Light",font:"'Inter',sans-serif",
    bg:"#f8fafc",surface:"#ffffff",surfaceHi:"#f1f5f9",
    border:"#e2e8f0",borderHi:"#cbd5e1",
    accent:"#10b981",accentDim:"#10b98112",accentText:"#059669",accentHover:"#059669",
    text:"#475569",textHi:"#1e293b",muted:"#94a3b8",mutedHi:"#64748b",
    white:"#0f172a",green:"#10b981",amber:"#f59e0b",red:"#ef4444",purple:"#8b5cf6",
    inputBg:"#ffffff",inputBorder:"#e2e8f0",inputText:"#0f172a",
    shadow:"0 1px 3px rgba(0,0,0,0.06),0 1px 2px rgba(0,0,0,0.04)",
    shadowMd:"0 4px 6px -1px rgba(0,0,0,0.07),0 2px 4px -1px rgba(0,0,0,0.04)",
    badge:"#f1f5f9",navActive:"#f0fdf4",navActiveBorder:"#10b981",
    statNum:"#0f172a",statLabel:"#10b981",
    sidebarBg:"#ffffff",topbarBg:"#ffffff",
  },
  // Professional dark — same aesthetic, dark slate
  dark:{
    name:"Dark",font:"'Inter',sans-serif",
    bg:"#0f172a",surface:"#1e293b",surfaceHi:"#334155",
    border:"#334155",borderHi:"#475569",
    accent:"#10b981",accentDim:"#10b98118",accentText:"#34d399",accentHover:"#34d399",
    text:"#94a3b8",textHi:"#e2e8f0",muted:"#64748b",mutedHi:"#94a3b8",
    white:"#f1f5f9",green:"#10b981",amber:"#f59e0b",red:"#f87171",purple:"#a78bfa",
    inputBg:"#1e293b",inputBorder:"#334155",inputText:"#f1f5f9",
    shadow:"0 1px 3px rgba(0,0,0,0.3)",
    shadowMd:"0 4px 6px -1px rgba(0,0,0,0.4)",
    badge:"#334155",navActive:"#10b98118",navActiveBorder:"#10b981",
    statNum:"#f1f5f9",statLabel:"#10b981",
    sidebarBg:"#1e293b",topbarBg:"#1e293b",
  },
  // Operator — keep for those who prefer the terminal aesthetic
  operator:{
    name:"Operator",font:"'Space Mono',monospace",
    bg:"#07070e",surface:"#0d0d1c",surfaceHi:"#111126",
    border:"#1a1a30",borderHi:"#2a2a45",
    accent:"#00e5c0",accentDim:"#00e5c014",accentText:"#00e5c0",accentHover:"#00e5c0",
    text:"#c4c4e0",textHi:"#f0f0ff",muted:"#484870",mutedHi:"#6868a0",
    white:"#f0f0ff",green:"#00e676",amber:"#ffab00",red:"#ff5252",purple:"#a78bfa",
    inputBg:"#0a0a18",inputBorder:"#2a2a45",inputText:"#e0e0f8",
    shadow:"0 2px 12px rgba(0,0,0,0.6)",shadowMd:"0 4px 24px rgba(0,0,0,0.5)",
    badge:"#141428",navActive:"#00e5c014",navActiveBorder:"#00e5c0",
    statNum:"#00e5c0",statLabel:"#484870",
    sidebarBg:"#0d0d1c",topbarBg:"#0d0d1c",
  },
};

// ── MODE NAV DEFINITIONS ──────────────────────────────────────────────────────
const IOC_NAV=[
  {id:"dashboard",label:"Dashboard",     icon:"grid"},
  {id:"feed",     label:"IOC Feed",      icon:"list"},
  {id:"add",      label:"Add IOC",       icon:"plus"},
  {id:"campaigns",label:"Campaigns",     icon:"folder"},
  {id:"map",      label:"Geo Map",       icon:"map"},
  {id:"public",   label:"Public Lookup", icon:"search"},
  {id:"import",   label:"Import",        icon:"upload"},
  {id:"export",   label:"Export",        icon:"download"},
];
const CVE_NAV=[
  {id:"dashboard",label:"Dashboard",     icon:"grid"},
  {id:"cve",      label:"CVE Monitor",   icon:"shield"},
  {id:"cvelookup",label:"CVE Lookup",    icon:"search"},
  {id:"cvewall",  label:"CVE Wall",      icon:"rss"},
  {id:"intel",    label:"Intel Wall",    icon:"rss"},
  {id:"actors",   label:"Threat Actors", icon:"users"},
  {id:"osint",    label:"OSINT",         icon:"radar"},
  {id:"querygen", label:"Query Builder", icon:"code"},
];
const ADMIN_NAV=[
  {id:"settings", label:"Settings",      icon:"settings"},
  {id:"users",    label:"Users",         icon:"usergroup"},
  {id:"invites",  label:"Invites",       icon:"mail"},
];
const USER_NAV=[
  {id:"settings", label:"Settings",      icon:"settings"},
];

// SVG nav icons — matches the clean icon style in the reference screenshots
function NavIcon({name,size=16,color="currentColor"}){
  const s={width:size,height:size,viewBox:"0 0 24 24",fill:"none",stroke:color,strokeWidth:2,strokeLinecap:"round",strokeLinejoin:"round",flexShrink:0};
  const icons={
    grid:     <svg {...s}><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>,
    list:     <svg {...s}><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>,
    plus:     <svg {...s}><circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>,
    folder:   <svg {...s}><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>,
    map:      <svg {...s}><polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6"/><line x1="8" y1="2" x2="8" y2="18"/><line x1="16" y1="6" x2="16" y2="22"/></svg>,
    search:   <svg {...s}><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
    upload:   <svg {...s}><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>,
    download: <svg {...s}><polyline points="8 17 12 21 16 17"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.88 18.09A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>,
    shield:   <svg {...s}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
    rss:      <svg {...s}><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>,
    users:    <svg {...s}><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>,
    radar:    <svg {...s}><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/></svg>,
    code:     <svg {...s}><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>,
    settings: <svg {...s}><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>,
    usergroup:<svg {...s}><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>,
    mail:     <svg {...s}><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>,
    bell:     <svg {...s}><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>,
    externalLink: <svg {...s}><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>,
    chevronRight: <svg {...s}><polyline points="9 18 15 12 9 6"/></svg>,
  };
  return icons[name]||<svg {...s}><circle cx="12" cy="12" r="4"/></svg>;
}

// ── CVE SUMMARY STRIP (shown on dashboard regardless of mode) ─────────────────
function CVESummaryStrip({token,C}){
  const [summary,setSummary]=useState(null);
  useEffect(()=>{
    api("/cves/stats/summary",{},token).then(r=>r.ok?r.json():null).then(d=>{if(d)setSummary(d);});
  },[token]);
  if(!summary||summary.total===0)return null;
  return(
    <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
      padding:"14px 20px",marginBottom:20,display:"flex",gap:24,alignItems:"center",
      flexWrap:"wrap",boxShadow:C.shadow}}>
      <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:1,
        textTransform:"uppercase",marginRight:4}}>CVE Monitor</div>
      {[[`${summary.total} Total`,C.accentText],[`${summary.unpatched} Unpatched`,C.red],
        [`${summary.kev_unpatched} KEV`,C.red],[`${summary.patched} Patched`,C.green],
      ].map(([label,color])=>(
        <div key={label} style={{fontSize:13,fontWeight:700,color}}>{label}</div>
      ))}
      {summary.last_poll&&(
        <div style={{fontSize:11,color:C.muted,marginLeft:"auto"}}>
          Last poll: {new Date(summary.last_poll).toLocaleString()}
        </div>
      )}
    </div>
  );
}

async function api(path,opts={},token=null){
  const headers={"Content-Type":"application/json",...(opts.headers||{})};
  if(token)headers["Authorization"]=`Bearer ${token}`;
  const r=await fetch(`${API_BASE}${path}`,{...opts,headers});
  if(r.status===401){localStorage.removeItem("tf_token");window.location.reload();}
  return r;
}
async function apiForm(path,body){
  return fetch(`${API_BASE}${path}`,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams(body)});
}

// ── ATOMS ─────────────────────────────────────────────────────────────────────
function TLPBadge({level}){
  const s=TLP_COLORS[level]??TLP_COLORS.WHITE;
  return <span style={{display:"inline-block",fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,color:s.color,background:s.bg,border:`1px solid ${s.color}40`}}>TLP:{level}</span>;
}
function Tag({label,C}){
  return <span style={{display:"inline-block",fontSize:11,padding:"2px 8px",borderRadius:4,color:C.muted,background:C.badge,border:`1px solid ${C.border}`,marginRight:4,marginBottom:4,whiteSpace:"nowrap"}}>{label}</span>;
}
// eslint-disable-next-line no-unused-vars
function ConfBar({val,C}){
  const color=val>=80?C.green:val>=50?C.amber:C.red;
  return(
    <div style={{display:"flex",alignItems:"center",gap:8}}>
      <div style={{width:56,height:4,background:C.border,borderRadius:2,overflow:"hidden"}}>
        <div style={{width:`${val}%`,height:"100%",background:color,borderRadius:2}}/>
      </div>
      <span style={{fontSize:12,color,fontWeight:700}}>{val}</span>
    </div>
  );
}
function Field({label,children,C}){
  return(
    <div style={{marginBottom:16}}>
      <label style={{display:"block",fontSize:12,color:C.muted,marginBottom:6,fontWeight:600}}>{label}</label>
      {children}
    </div>
  );
}
function Inp({value,onChange,type="text",placeholder,C,rows}){
  const base={width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"10px 14px",borderRadius:8,fontSize:14,outline:"none",boxSizing:"border-box",fontFamily:"inherit"};
  if(rows)return <textarea value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} rows={rows} style={{...base,resize:"vertical"}}/>;
  return <input type={type} value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} style={base}/>;
}
function Sel({value,onChange,options,C}){
  return <select value={value} onChange={e=>onChange(e.target.value)} style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"10px 12px",borderRadius:8,fontSize:14,outline:"none",fontFamily:"inherit"}}>
    {options.map(o=><option key={o} value={o}>{o}</option>)}
  </select>;
}
function Btn({onClick,disabled,children,variant="primary",C,full,sm}){
  const s={primary:{background:C.accent,color:"#fff",border:"none",boxShadow:C.glow||"none"},ghost:{background:"transparent",color:C.muted,border:`1px solid ${C.border}`},danger:{background:"transparent",color:C.red,border:`1px solid ${C.red}50`},dim:{background:C.accentDim,color:C.accentText,border:`1px solid ${C.accent}40`},success:{background:C.green+"20",color:C.green,border:`1px solid ${C.green}40`}};
  return <button onClick={onClick} disabled={disabled} style={{padding:sm?"6px 12px":"10px 20px",borderRadius:8,cursor:disabled?"not-allowed":"pointer",fontSize:sm?12:14,fontFamily:"inherit",fontWeight:600,width:full?"100%":"auto",opacity:disabled?0.4:1,transition:"all .15s",...(s[variant]||s.primary)}}>{children}</button>;
}
function Card({C,children,style={}}){
  return <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:20,boxShadow:C.shadow,...style}}>{children}</div>;
}
function StatCard({label,value,color,C,sublabel}){
  return(
    <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
      padding:"22px 24px",boxShadow:C.shadow,transition:"box-shadow .15s"}}>
      <div style={{display:"flex",alignItems:"baseline",gap:6,marginBottom:6}}>
        <span style={{fontSize:38,fontWeight:700,letterSpacing:"-0.02em",
          color:C.statNum,lineHeight:1}}>{typeof value==="number"?value.toLocaleString():value}</span>
        {sublabel&&<span style={{fontSize:13,fontWeight:600,color:color||C.statLabel}}>{sublabel}</span>}
      </div>
      <div style={{fontSize:13,color:C.muted,fontWeight:500}}>{label}</div>
    </div>
  );
}

// ── CVE ATOMS ─────────────────────────────────────────────────────────────────
function SevBadge({severity,score,C}){
  const s=String(severity||"").toUpperCase();
  const map={CRITICAL:{bg:C.red+"20",color:C.red},HIGH:{bg:C.amber+"20",color:C.amber},MEDIUM:{bg:C.purple+"20",color:C.purple},LOW:{bg:C.green+"20",color:C.green}};
  const style=map[s]||{bg:C.muted+"20",color:C.muted};
  return <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,background:style.bg,color:style.color,border:`1px solid ${style.color}40`}}>{s||"?"}{score?` ${score}`:""}</span>;
}
function PatchBadge({available,url,C}){
  if(available)return(
    <span style={{display:"inline-flex",alignItems:"center",gap:4,fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,background:C.green+"20",color:C.green,border:`1px solid ${C.green}40`}}>
      ✅ Patch Available{url&&<a href={url} target="_blank" rel="noreferrer" style={{color:C.green,fontSize:10,marginLeft:4}}>→</a>}
    </span>
  );
  return <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,background:C.red+"20",color:C.red,border:`1px solid ${C.red}40`}}>❌ No Patch</span>;
}

// ── NOTIFICATION BELL ─────────────────────────────────────────────────────────
function NotificationBell({token,C,isAdmin}){
  const [count,setCount]=useState(0);
  const [open,setOpen]=useState(false);
  const [notifs,setNotifs]=useState([]);
  const [loading,setLoading]=useState(false);
  const ref=useRef(null);

  useEffect(()=>{
    if(!isAdmin)return;
    const poll=()=>api("/notifications/count",{},token).then(r=>r.ok?r.json():null).then(d=>{if(d)setCount(d.count);});
    poll();
    const interval=setInterval(poll,30000);
    return()=>clearInterval(interval);
  },[token,isAdmin]);

  useEffect(()=>{
    const h=e=>{if(ref.current&&!ref.current.contains(e.target))setOpen(false);};
    document.addEventListener("mousedown",h);return()=>document.removeEventListener("mousedown",h);
  },[]);

  async function openPanel(){
    setOpen(p=>!p);
    if(!open){
      setLoading(true);
      const r=await api("/notifications",{},token);
      if(r.ok)setNotifs(await r.json());
      setLoading(false);
    }
  }

  async function markRead(id){
    await api(`/notifications/${id}/read`,{method:"PATCH"},token);
    setNotifs(p=>p.map(n=>n.id===id?{...n,read:true}:n));
    setCount(p=>Math.max(0,p-1));
  }

  async function markAllRead(){
    await api("/notifications/read-all",{method:"PATCH"},token);
    setNotifs(p=>p.map(n=>({...n,read:true})));
    setCount(0);
  }

  if(!isAdmin)return null;

  const SEV_COLOR={critical:C.red,warning:C.amber,success:C.green,info:C.accentText};
  const TYPE_ICON={cve_new:"🛡️",ioc_auto:"⚡",patch_available:"✅",default:"🔔"};

  return(
    <div ref={ref} style={{position:"relative"}}>
      <button onClick={openPanel} style={{position:"relative",background:"none",border:`1px solid ${C.border}`,color:C.muted,borderRadius:8,padding:"7px 10px",cursor:"pointer",fontSize:16,display:"flex",alignItems:"center",gap:4}}>
        🔔
        {count>0&&(
          <span style={{position:"absolute",top:-6,right:-6,background:C.red,color:"#fff",fontSize:10,fontWeight:700,borderRadius:"50%",minWidth:18,height:18,display:"flex",alignItems:"center",justifyContent:"center",padding:"0 3px",lineHeight:1}}>
            {count>99?"99+":count}
          </span>
        )}
      </button>

      {open&&(
        <div style={{position:"absolute",top:"calc(100% + 8px)",right:0,width:380,maxHeight:520,overflowY:"auto",background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,boxShadow:C.shadow,zIndex:400}}>
          <div style={{padding:"14px 16px",borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center",position:"sticky",top:0,background:C.surface}}>
            <div style={{fontSize:13,fontWeight:700,color:C.white}}>Notifications {count>0&&<span style={{fontSize:11,color:C.red,fontWeight:700}}>({count} unread)</span>}</div>
            {count>0&&<button onClick={markAllRead} style={{fontSize:11,color:C.accentText,background:"none",border:"none",cursor:"pointer",fontFamily:"inherit",fontWeight:600}}>Mark all read</button>}
          </div>

          {loading&&<div style={{padding:24,textAlign:"center",color:C.muted,fontSize:13}}>Loading...</div>}
          {!loading&&notifs.length===0&&(
            <div style={{padding:32,textAlign:"center",color:C.muted,fontSize:13}}>
              <div style={{fontSize:24,marginBottom:8}}>🔔</div>
              No notifications yet
            </div>
          )}
          {notifs.map(n=>{
            const color=SEV_COLOR[n.severity]||C.accentText;
            const icon=TYPE_ICON[n.type]||TYPE_ICON.default;
            return(
              <div key={n.id} onClick={()=>!n.read&&markRead(n.id)}
                style={{padding:"12px 16px",borderBottom:`1px solid ${C.border}20`,cursor:n.read?"default":"pointer",background:n.read?"transparent":color+"08",transition:"background .15s"}}
                onMouseEnter={e=>!n.read&&(e.currentTarget.style.background=color+"12")}
                onMouseLeave={e=>!n.read&&(e.currentTarget.style.background=color+"08")}>
                <div style={{display:"flex",gap:10,alignItems:"flex-start"}}>
                  <span style={{fontSize:18,flexShrink:0,marginTop:1}}>{icon}</span>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:8,marginBottom:4}}>
                      <div style={{fontSize:12,fontWeight:700,color:n.read?C.muted:C.white,lineHeight:1.3}}>{n.title}</div>
                      {!n.read&&<div style={{width:8,height:8,borderRadius:"50%",background:color,flexShrink:0,marginTop:3}}/>}
                    </div>
                    {n.body&&<div style={{fontSize:11,color:C.muted,lineHeight:1.5,marginBottom:4}}>{n.body.slice(0,120)}{n.body.length>120?"...":""}</div>}
                    <div style={{fontSize:10,color:C.muted}}>{new Date(n.created_at).toLocaleString()}</div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── CVE DETAIL MODAL ──────────────────────────────────────────────────────────
// ── CVE REPORT MODAL ─────────────────────────────────────────────────────────
// Simple inline markdown renderer — no library needed
function renderMarkdown(text, C){
  if(!text) return null;
  const lines = text.split('\n');
  return lines.map((line, i) => {
    // Render inline **bold** within a line
    function inlineBold(str){
      const parts = str.split(/\*\*(.*?)\*\*/g);
      return parts.map((p, j) => j % 2 === 1
        ? <strong key={j} style={{fontWeight:700, color:C.white||C.textHi}}>{p}</strong>
        : p
      );
    }

    // H1
    if(/^# /.test(line))
      return <div key={i} style={{fontSize:16,fontWeight:800,color:C.white||C.textHi,
        marginTop:16,marginBottom:8,lineHeight:1.4}}>{line.replace(/^# /,'')}</div>;
    // H2
    if(/^## /.test(line))
      return <div key={i} style={{fontSize:14,fontWeight:700,color:C.white||C.textHi,
        marginTop:14,marginBottom:6,borderBottom:`1px solid ${C.border}`,
        paddingBottom:4,lineHeight:1.4}}>{line.replace(/^## /,'')}</div>;
    // H3
    if(/^### /.test(line))
      return <div key={i} style={{fontSize:13,fontWeight:700,color:C.accentText,
        marginTop:10,marginBottom:4}}>{line.replace(/^### /,'')}</div>;
    // Table row (markdown table |col|col|)
    if(/^\|/.test(line)&&line.trim().endsWith('|')){
      const cells=line.split('|').filter((_,j)=>j>0&&j<line.split('|').length-1);
      const isSep=cells.every(c=>/^[-: ]+$/.test(c));
      if(isSep) return null;
      return(
        <div key={i} style={{display:'flex',gap:0,marginBottom:2}}>
          {cells.map((cell,j)=>(
            <div key={j} style={{flex:1,padding:'5px 10px',fontSize:12,
              background:j===0?C.surfaceHi:"transparent",
              border:`1px solid ${C.border}20`,
              color:j===0?C.muted:C.text,fontWeight:j===0?600:400}}>
              {inlineBold(cell.trim())}
            </div>
          ))}
        </div>
      );
    }
    // Bullet
    if(/^[-*•] /.test(line))
      return <div key={i} style={{display:'flex',gap:8,marginBottom:3,
        paddingLeft:8,fontSize:12,color:C.text,lineHeight:1.6}}>
        <span style={{color:C.accentText,flexShrink:0}}>•</span>
        <span>{inlineBold(line.replace(/^[-*•] /,''))}</span>
      </div>;
    // Numbered list
    if(/^\d+\. /.test(line))
      return <div key={i} style={{display:'flex',gap:8,marginBottom:3,
        paddingLeft:8,fontSize:12,color:C.text,lineHeight:1.6}}>
        <span style={{color:C.accentText,fontWeight:600,flexShrink:0,minWidth:18}}>
          {line.match(/^\d+/)[0]}.
        </span>
        <span>{inlineBold(line.replace(/^\d+\. /,''))}</span>
      </div>;
    // URL line
    if(/^https?:\/\//.test(line.trim()))
      return <a key={i} href={line.trim()} target="_blank" rel="noreferrer"
        style={{display:'block',fontSize:11,color:C.accentText,marginBottom:3,
          wordBreak:'break-all',paddingLeft:8}}>{line.trim()}</a>;
    // Empty line
    if(!line.trim())
      return <div key={i} style={{height:6}}/>;
    // Default paragraph
    return <div key={i} style={{fontSize:12,color:C.text,lineHeight:1.7,marginBottom:2}}>
      {inlineBold(line)}
    </div>;
  }).filter(Boolean);
}

function CVEReportModal({cveId,token,C,onClose}){
  const [format,setFormat]=useState("email");
  const [result,setResult]=useState(null);
  const [loading,setLoading]=useState(false);
  const [err,setErr]=useState("");
  const [copied,setCopied]=useState(false);

  async function generate(){
    setLoading(true);setErr("");setResult(null);
    try{
      const r=await api(`/cve/report?id=${encodeURIComponent(cveId)}&format=${format}`,{},token);
      if(r.ok) setResult(await r.json());
      else {const e=await r.json();setErr(e.detail||"Generation failed.");}
    }catch{setErr("Cannot reach server.");}
    setLoading(false);
  }

  function copy(){
    const text=result?.subject?`Subject: ${result.subject}\n\n${result.content}`:result?.content||"";
    navigator.clipboard.writeText(text);setCopied(true);setTimeout(()=>setCopied(false),2000);
  }

  function openEmail(){
    const subject=encodeURIComponent(result?.subject||`Security Advisory: ${cveId}`);
    const body=encodeURIComponent(result?.content||"");
    window.open(`mailto:?subject=${subject}&body=${body}`);
  }

  const SEV_COLORS={CRITICAL:C.red,HIGH:C.amber,MEDIUM:C.purple,LOW:C.green,
                    Critical:C.red,High:C.amber,Medium:C.purple,Low:C.green};

  return(
    <div style={{position:"fixed",inset:0,background:"#00000095",zIndex:900,
      display:"flex",alignItems:"center",justifyContent:"center",padding:16}}
      onClick={onClose}>
      <div onClick={e=>e.stopPropagation()}
        style={{width:"100%",maxWidth:760,maxHeight:"90vh",display:"flex",flexDirection:"column",
          background:C.surface,border:`1px solid ${C.border}`,borderRadius:16,
          boxShadow:C.shadow}}>

        {/* Header */}
        <div style={{padding:"18px 24px",borderBottom:`1px solid ${C.border}`,
          display:"flex",justifyContent:"space-between",alignItems:"center",
          flexShrink:0}}>
          <div>
            <div style={{fontSize:15,fontWeight:700,color:C.white||C.textHi,marginBottom:2}}>
              Generate CVE Report
            </div>
            <div style={{fontSize:12,color:C.muted,fontFamily:"monospace"}}>{cveId}</div>
          </div>
          <button onClick={onClose} style={{background:"none",border:"none",color:C.muted,
            fontSize:20,cursor:"pointer",padding:0}}>×</button>
        </div>

        {/* Format picker + Generate */}
        <div style={{padding:"16px 24px",borderBottom:`1px solid ${C.border}`,
          display:"flex",gap:12,alignItems:"center",flexShrink:0}}>
          <div style={{display:"flex",background:C.surfaceHi,borderRadius:8,padding:3,gap:2}}>
            {[["email","📧 Email Draft"],["summary","📋 Summary Brief"]].map(([val,label])=>(
              <button key={val} onClick={()=>{setFormat(val);setResult(null);setErr("");}}
                style={{padding:"7px 16px",borderRadius:6,border:"none",cursor:"pointer",
                  fontSize:12,fontFamily:"inherit",fontWeight:600,
                  background:format===val?C.accent:"transparent",
                  color:format===val?"#fff":C.muted}}>
                {label}
              </button>
            ))}
          </div>
          <Btn onClick={generate} disabled={loading} C={C}>
            {loading?"Generating...":"⚡ Generate"}
          </Btn>
          {result&&(
            <>
              <button onClick={copy}
                style={{padding:"7px 14px",background:copied?C.green+"20":C.accentDim,
                  border:`1px solid ${copied?C.green:C.accent}40`,color:copied?C.green:C.accentText,
                  borderRadius:7,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600}}>
                {copied?"✓ Copied":"Copy"}
              </button>
              {format==="email"&&(
                <button onClick={openEmail}
                  style={{padding:"7px 14px",background:C.surfaceHi,
                    border:`1px solid ${C.border}`,color:C.text,
                    borderRadius:7,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600}}>
                  Open in Mail ↗
                </button>
              )}
            </>
          )}
        </div>

        {/* Body */}
        <div style={{flex:1,overflowY:"auto",padding:"16px 24px"}}>
          {err&&<div style={{padding:"10px 14px",background:C.red+"10",border:`1px solid ${C.red}30`,
            borderRadius:8,color:C.red,fontSize:13,marginBottom:12}}>{err}</div>}

          {loading&&(
            <div style={{textAlign:"center",padding:48,color:C.muted}}>
              <div style={{fontSize:14,fontWeight:600,color:C.white||C.textHi,marginBottom:8}}>
                Checking for PoC exploits &amp; building report...
              </div>
              <div style={{fontSize:12}}>
                Querying GitHub PoC database, ExploitDB, and NVD references
              </div>
            </div>
          )}

          {!loading&&!result&&!err&&(
            <div style={{textAlign:"center",padding:40,color:C.muted}}>
              <div style={{fontSize:32,marginBottom:12}}>
                {format==="email"?"📧":"📋"}
              </div>
              <div style={{fontSize:13,marginBottom:6,color:C.white||C.textHi,fontWeight:600}}>
                {format==="email"?"Professional Security Advisory Email":"Structured CVE Summary Brief"}
              </div>
              <div style={{fontSize:12,lineHeight:1.7,maxWidth:400,margin:"0 auto"}}>
                {format==="email"
                  ?"Includes vulnerability overview, affected products, exploit conditions, PoC status, mitigation steps, and references. Ready to forward to IT/management."
                  :"Structured markdown report with CVSS breakdown table, exploit conditions, PoC links (if any), and full reference list."}
              </div>
            </div>
          )}

          {result&&(
            <div>
              {/* PoC status banner */}
              <div style={{marginBottom:12,padding:"10px 14px",borderRadius:8,
                background:result.poc?.available?C.red+"08":C.green+"08",
                border:`1px solid ${result.poc?.available?C.red:C.green}30`,
                display:"flex",alignItems:"center",gap:10}}>
                <span style={{fontSize:16}}>
                  {result.poc?.available?"🚨":"✅"}
                </span>
                <div style={{flex:1}}>
                  <span style={{fontSize:13,fontWeight:700,
                    color:result.poc?.available?C.red:C.green}}>
                    PoC Exploits: {result.poc?.available
                      ?`${result.poc.count} source${result.poc.count!==1?"s":""} found`
                      :"None Found"}
                  </span>
                  {result.poc?.available&&result.poc?.top&&(
                    <div style={{fontSize:11,color:C.muted,marginTop:2}}>
                      Top: <span style={{color:C.accentText,fontWeight:600}}>
                        {result.poc.top.source}
                      </span>
                      {result.poc.top.stars>0&&` · ⭐ ${result.poc.top.stars}`}
                      {result.poc.top.description&&` · ${result.poc.top.description.slice(0,60)}...`}
                    </div>
                  )}
                </div>
                <div style={{display:"flex",gap:6,alignItems:"center",flexShrink:0}}>
                  <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,
                    background:(SEV_COLORS[result.severity]||C.muted)+"20",
                    color:SEV_COLORS[result.severity]||C.muted}}>
                    {result.severity} {result.score}
                  </span>
                </div>
              </div>

              {/* Email subject */}
              {format==="email"&&result.subject&&(
                <div style={{marginBottom:12,padding:"10px 14px",background:C.surfaceHi,
                  border:`1px solid ${C.border}`,borderRadius:8}}>
                  <span style={{fontSize:10,color:C.muted,fontWeight:700,
                    textTransform:"uppercase",letterSpacing:"0.05em"}}>Subject: </span>
                  <span style={{fontSize:13,color:C.white||C.textHi,fontWeight:600}}>
                    {result.subject}
                  </span>
                </div>
              )}

              {/* Content */}
              <div style={{background:C.surfaceHi,border:`1px solid ${C.border}`,
                borderRadius:10,padding:"16px 18px"}}>
                {renderMarkdown(result.content, C)}
              </div>

              {/* PoC links */}
              {result.poc?.available&&result.poc?.results?.length>0&&(
                <div style={{marginTop:12,padding:"14px 16px",background:C.red+"08",
                  border:`1px solid ${C.red}20`,borderRadius:10}}>
                  <div style={{fontSize:11,color:C.red,fontWeight:700,marginBottom:10,
                    textTransform:"uppercase",letterSpacing:"0.05em"}}>
                    🔓 PoC / Exploit References ({result.poc.count} found)
                  </div>
                  {result.poc.results.map((poc,i)=>{
                    const QUAL_COLOR={"verified":C.red,"high":C.amber,"medium":C.purple,"low":C.muted};
                    const QUAL_LABEL={"verified":"✓ Verified","high":"★ High","medium":"◎ Medium","low":"○ Low"};
                    return(
                      <div key={i} style={{marginBottom:8,padding:"8px 12px",
                        background:C.surfaceHi,borderRadius:7,
                        border:`1px solid ${(QUAL_COLOR[poc.quality]||C.muted)}30`}}>
                        <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4,flexWrap:"wrap"}}>
                          <span style={{fontSize:10,padding:"1px 7px",borderRadius:4,fontWeight:700,
                            background:(QUAL_COLOR[poc.quality]||C.muted)+"20",
                            color:QUAL_COLOR[poc.quality]||C.muted,flexShrink:0}}>
                            {QUAL_LABEL[poc.quality]||poc.quality}
                          </span>
                          <span style={{fontSize:11,color:C.accentText,fontWeight:600,flexShrink:0}}>
                            {poc.source}
                          </span>
                          {poc.stars>0&&(
                            <span style={{fontSize:10,color:C.amber}}>⭐ {poc.stars}</span>
                          )}
                          {poc.language&&(
                            <span style={{fontSize:10,color:C.muted,marginLeft:"auto"}}>
                              {poc.language}
                            </span>
                          )}
                        </div>
                        <a href={poc.url} target="_blank" rel="noreferrer"
                          style={{fontSize:11,color:C.accentText,wordBreak:"break-all",
                            display:"flex",alignItems:"center",gap:4,marginBottom:poc.description?4:0}}>
                          <NavIcon name="externalLink" size={10} color={C.accentText}/>{poc.url}
                        </a>
                        {poc.description&&(
                          <div style={{fontSize:11,color:C.muted,lineHeight:1.5,paddingLeft:14}}>
                            {poc.description}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── CVE DETAIL — OpenCVE-parity full-panel view ──────────────────────────────
function CVEDetail({cve,token,onClose,C}){
  const [enriched,setEnriched]=useState(null);
  const [loading,setLoading]=useState(true);
  const [tab,setTab]=useState("overview");
  const [showReport,setShowReport]=useState(false);

  useEffect(()=>{
    setLoading(true);setEnriched(null);setTab("overview");
    // Fetch from multi-source lookup for enriched data
    api(`/cve/lookup?id=${encodeURIComponent(cve.cve_id)}`,{},token)
      .then(r=>r.ok?r.json():null)
      .then(d=>{if(d)setEnriched(d);setLoading(false);})
      .catch(()=>setLoading(false));
  },[cve.cve_id,token]);// eslint-disable-line react-hooks/exhaustive-deps

  const d=cve;
  const nvd=enriched?.sources?.find(s=>s.source==="NVD"&&s.status==="ok");
  const cveOrg=enriched?.sources?.find(s=>s.source==="CVE.org"&&s.status==="ok");
  const osv=enriched?.sources?.find(s=>s.source==="OSV"&&s.status==="ok");
  const epss=enriched?.epss;
  const inKev=enriched?.in_kev||d.kev_listed;
  const kevDate=enriched?.kev_date||d.kev_date;

  // Merge references from all sources + DB, deduplicated
  const allRefs=[...(d.references||[]),...(nvd?.references||[])]
    .reduce((acc,r)=>{
      const url=r?.url||r;
      if(url&&!acc.find(x=>x.url===url)) acc.push({url,tags:r?.tags||[]});
      return acc;
    },[]);

  const CVSS_META={
    AV:{label:"Attack Vector",   N:{l:"Network",   risk:3},A:{l:"Adjacent",risk:2},L:{l:"Local",  risk:1},P:{l:"Physical",risk:0}},
    AC:{label:"Attack Complexity",L:{l:"Low",       risk:2},H:{l:"High",   risk:0}},
    PR:{label:"Privileges Req.",  N:{l:"None",      risk:2},L:{l:"Low",    risk:1},H:{l:"High",   risk:0}},
    UI:{label:"User Interaction", N:{l:"None",      risk:2},R:{l:"Required",risk:0}},
    S: {label:"Scope",            C:{l:"Changed",   risk:2},U:{l:"Unchanged",risk:0}},
    C: {label:"Confidentiality",  H:{l:"High",      risk:2},L:{l:"Low",    risk:1},N:{l:"None",   risk:0}},
    I: {label:"Integrity",        H:{l:"High",      risk:2},L:{l:"Low",    risk:1},N:{l:"None",   risk:0}},
    A: {label:"Availability",     H:{l:"High",      risk:2},L:{l:"Low",    risk:1},N:{l:"None",   risk:0}},
  };

  function parseCVSS(vec){
    if(!vec) return null;
    const m={}; (vec||"").replace("CVSS:3.1/","").replace("CVSS:3.0/","").split("/").forEach(p=>{
      const [k,v]=p.split(":"); if(k&&v) m[k]=v;
    }); return m;
  }
  const cvssMetrics=parseCVSS(d.cvss_vector||nvd?.cvss?.vector);

  function cvssRiskColor(key,val){
    const risk=CVSS_META[key]?.[val]?.risk??0;
    return risk>=2?C.red:risk===1?C.amber:C.muted;
  }
  function cvssRiskBg(key,val){
    const risk=CVSS_META[key]?.[val]?.risk??0;
    return risk>=2?C.red+"20":risk===1?C.amber+"20":C.surfaceHi;
  }

  // Categorize references
  const REF_CATS={
    Patch:["Patch","Fix","Mitigation"],
    Advisory:["Vendor Advisory","Third Party Advisory"],
    Exploit:["Exploit","Proof of Concept"],
    Technical:["Technical Description","Issue Tracking"],
    Other:[]
  };
  function categorizeRef(tags){
    if(!tags?.length) return "Other";
    for(const[cat,keywords] of Object.entries(REF_CATS)){
      if(tags.some(t=>keywords.some(k=>t.toLowerCase().includes(k.toLowerCase())))) return cat;
    }
    return "Other";
  }
  const refsByCategory=allRefs.reduce((acc,ref)=>{
    const cat=categorizeRef(ref.tags);
    if(!acc[cat]) acc[cat]=[];
    acc[cat].push(ref); return acc;
  },{});

  const score=d.cvss_score;
  const scoreColor=score>=9?C.red:score>=7?C.amber:score>=4?C.purple:C.green;
  const sevLabel=d.cvss_severity||nvd?.cvss?.severity||"";

  const TABS=[
    {id:"overview",  label:"Overview"},
    {id:"cvss",      label:"CVSS Details"},
    {id:"references",label:`References (${allRefs.length})`},
    {id:"sources",   label:"All Sources"},
  ];
  if(osv?.vulns?.length>0) TABS.splice(3,0,{id:"packages",label:"Affected Packages"});

  return(
    <div style={{position:"fixed",inset:0,background:"#00000095",display:"flex",
      alignItems:"flex-start",justifyContent:"flex-end",zIndex:600,padding:0}}
      onClick={onClose}>
      <div onClick={e=>e.stopPropagation()}
        style={{width:"min(820px,100%)",height:"100vh",overflowY:"auto",
          background:C.surface,borderLeft:`1px solid ${C.border}`,
          boxShadow:"-8px 0 40px #0006"}}>

        {/* ── Header ── */}
        <div style={{padding:"20px 24px 0",borderBottom:`1px solid ${C.border}`,
          background:C.surfaceHi,position:"sticky",top:0,zIndex:10}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:14}}>
            <div style={{flex:1,minWidth:0,marginRight:12}}>
              <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:6,flexWrap:"wrap"}}>
                <span style={{fontSize:16,fontWeight:800,color:C.accentText,fontFamily:"monospace",
                  letterSpacing:"-0.01em"}}>{d.cve_id}</span>
                {inKev&&<span style={{fontSize:11,padding:"3px 9px",borderRadius:5,fontWeight:700,
                  background:C.red+"20",color:C.red,border:`1px solid ${C.red}40`}}>🚨 CISA KEV</span>}
                {d.patch_available&&<span style={{fontSize:11,padding:"3px 9px",borderRadius:5,fontWeight:700,
                  background:C.green+"20",color:C.green,border:`1px solid ${C.green}40`}}>✅ Patch Available</span>}
                <a href={`https://nvd.nist.gov/vuln/detail/${d.cve_id}`} target="_blank" rel="noreferrer"
                  style={{fontSize:11,color:C.muted,display:"flex",alignItems:"center",gap:3}}>
                  <NavIcon name="externalLink" size={11} color={C.muted}/>NVD
                </a>
              </div>
              {d.asset_name&&<div style={{fontSize:12,color:C.muted}}>
                Asset: <span style={{color:C.accentText,fontWeight:600}}>{d.asset_name}</span>
              </div>}
            </div>

            {/* Big score */}
            <div style={{display:"flex",gap:8,alignItems:"center",flexShrink:0}}>
              {score&&(
                <div style={{textAlign:"center"}}>
                  <div style={{fontSize:32,fontWeight:800,color:scoreColor,lineHeight:1}}>{score}</div>
                  <div style={{fontSize:10,color:scoreColor,fontWeight:700,letterSpacing:"0.05em",
                    textTransform:"uppercase"}}>{sevLabel}</div>
                </div>
              )}
              {epss&&(
                <div style={{textAlign:"center",padding:"6px 12px",background:C.accentDim,
                  border:`1px solid ${C.accent}30`,borderRadius:8}}>
                  <div style={{fontSize:18,fontWeight:700,color:C.accentText}}>
                    {(epss.epss*100).toFixed(1)}%
                  </div>
                  <div style={{fontSize:10,color:C.muted,fontWeight:600}}>EPSS</div>
                </div>
              )}
              <button onClick={()=>setShowReport(true)}
                style={{padding:"7px 14px",background:C.accent,border:"none",color:"#fff",
                  borderRadius:8,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:700}}>
                ⚡ Report
              </button>
              <button onClick={onClose} style={{background:"none",border:"none",color:C.muted,
                fontSize:22,cursor:"pointer",padding:"0 4px",lineHeight:1}}>×</button>
            </div>
          </div>
          {showReport&&<CVEReportModal cveId={d.cve_id} token={token} C={C} onClose={()=>setShowReport(false)}/>}


          {/* Score bar */}
          {score&&(
            <div style={{marginBottom:14}}>
              <div style={{height:6,background:C.border,borderRadius:3,overflow:"hidden",position:"relative"}}>
                <div style={{position:"absolute",left:0,top:0,height:"100%",borderRadius:3,
                  width:`${(score/10)*100}%`,
                  background:`linear-gradient(90deg, ${C.green}, ${C.amber} 50%, ${C.red})`}}/>
                <div style={{position:"absolute",top:-3,height:12,width:3,borderRadius:2,
                  background:C.white||"#fff",left:`calc(${(score/10)*100}% - 1px)`}}/>
              </div>
              <div style={{display:"flex",justifyContent:"space-between",fontSize:9,
                color:C.muted,marginTop:3}}>
                <span>0.0 None</span><span>4.0 Low</span><span>7.0 High</span><span>9.0 Critical</span>
              </div>
            </div>
          )}

          {/* Tabs */}
          <div style={{display:"flex",gap:0,overflowX:"auto"}}>
            {TABS.map(t=>(
              <button key={t.id} onClick={()=>setTab(t.id)}
                style={{padding:"8px 16px",border:"none",cursor:"pointer",fontFamily:"inherit",
                  fontSize:12,fontWeight:600,background:"transparent",
                  color:tab===t.id?C.accentText:C.muted,whiteSpace:"nowrap",
                  borderBottom:tab===t.id?`2px solid ${C.accentText}`:"2px solid transparent"}}>
                {t.label}
              </button>
            ))}
          </div>
        </div>

        {/* ── Body ── */}
        <div style={{padding:"20px 24px"}}>

          {/* ── OVERVIEW TAB ── */}
          {tab==="overview"&&(
            <div>
              {/* Description */}
              <div style={{fontSize:13,color:C.text,lineHeight:1.8,padding:"14px 16px",
                background:C.surfaceHi,borderRadius:10,marginBottom:18,border:`1px solid ${C.border}`}}>
                {d.description||nvd?.description||"No description available."}
              </div>

              {/* Timeline */}
              <div style={{marginBottom:18}}>
                <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:10,
                  textTransform:"uppercase",letterSpacing:"0.06em"}}>Timeline</div>
                <div style={{display:"flex",gap:0,flexWrap:"wrap"}}>
                  {[
                    {label:"Published",  date:d.published_date||nvd?.published,     color:C.accentText},
                    {label:"Modified",   date:d.modified_date||nvd?.modified,       color:C.muted},
                    {label:"KEV Added",  date:kevDate,                               color:C.red,   show:inKev},
                    {label:"Patch Found",date:d.patch_detected_at?.slice(0,10),     color:C.green, show:d.patch_available},
                  ].filter(x=>x.date&&x.show!==false).map((item,i,arr)=>(
                    <div key={item.label} style={{display:"flex",alignItems:"center"}}>
                      <div style={{textAlign:"center",padding:"6px 14px",
                        background:C.surfaceHi,border:`1px solid ${C.border}`,
                        borderRadius:i===0?"8px 0 0 8px":i===arr.length-1?"0 8px 8px 0":"0",
                        borderLeft:i>0?"none":"auto"}}>
                        <div style={{fontSize:10,color:item.color,fontWeight:600,marginBottom:2}}>
                          {item.label}
                        </div>
                        <div style={{fontSize:12,color:C.text,fontWeight:500,fontFamily:"monospace"}}>
                          {item.date?.slice(0,10)||"—"}
                        </div>
                      </div>
                      {i<arr.length-1&&<div style={{fontSize:14,color:C.muted}}>→</div>}
                    </div>
                  ))}
                </div>
              </div>

              {/* Scores grid */}
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(130px,1fr))",
                gap:10,marginBottom:18}}>
                {/* CVSS */}
                <div style={{padding:"12px 14px",background:C.surfaceHi,
                  border:`1px solid ${score>=9?C.red:score>=7?C.amber:C.border}30`,borderRadius:10}}>
                  <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:6,textTransform:"uppercase"}}>CVSS v{nvd?.cvss?.version||"3.1"}</div>
                  <div style={{fontSize:22,fontWeight:800,color:scoreColor,lineHeight:1}}>{score||"N/A"}</div>
                  <div style={{fontSize:10,color:scoreColor,fontWeight:600,marginTop:2}}>{sevLabel}</div>
                </div>
                {/* EPSS */}
                {epss&&(
                  <div style={{padding:"12px 14px",background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:10}}>
                    <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:6,textTransform:"uppercase"}}>EPSS Score</div>
                    <div style={{fontSize:22,fontWeight:800,color:C.accentText,lineHeight:1}}>
                      {(epss.epss*100).toFixed(2)}%
                    </div>
                    <div style={{fontSize:10,color:C.muted,marginTop:2}}>
                      Top {(100-epss.percentile*100).toFixed(0)}% exploited
                    </div>
                    {/* Percentile bar */}
                    <div style={{marginTop:6,height:3,background:C.border,borderRadius:2,overflow:"hidden"}}>
                      <div style={{width:`${epss.percentile*100}%`,height:"100%",background:C.accent,borderRadius:2}}/>
                    </div>
                  </div>
                )}
                {/* KEV */}
                <div style={{padding:"12px 14px",background:inKev?C.red+"08":C.surfaceHi,
                  border:`1px solid ${inKev?C.red+"40":C.border}`,borderRadius:10}}>
                  <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:6,textTransform:"uppercase"}}>CISA KEV</div>
                  <div style={{fontSize:14,fontWeight:700,color:inKev?C.red:C.muted}}>
                    {inKev?"In Catalog":"Not Listed"}
                  </div>
                  {kevDate&&<div style={{fontSize:10,color:C.muted,marginTop:2}}>Added {kevDate}</div>}
                </div>
                {/* CWE */}
                {d.cwe&&(
                  <div style={{padding:"12px 14px",background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:10}}>
                    <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:6,textTransform:"uppercase"}}>Weakness</div>
                    <div style={{fontSize:13,fontWeight:700,color:C.purple}}>{d.cwe}</div>
                    <a href={`https://cwe.mitre.org/data/definitions/${d.cwe.replace("CWE-","")}.html`}
                      target="_blank" rel="noreferrer"
                      style={{fontSize:10,color:C.muted,marginTop:2,display:"block"}}>
                      View on MITRE →
                    </a>
                  </div>
                )}
              </div>

              {/* Patch section */}
              {d.patch_available&&d.patch_url&&(
                <div style={{padding:"14px 16px",background:C.green+"08",
                  border:`1px solid ${C.green}30`,borderRadius:10,marginBottom:18}}>
                  <div style={{fontSize:11,fontWeight:700,color:C.green,marginBottom:8}}>
                    ✅ Vendor Patch / Advisory Available
                  </div>
                  {d.patch_detected_at&&(
                    <div style={{fontSize:11,color:C.muted,marginBottom:8}}>
                      Detected: {new Date(d.patch_detected_at).toLocaleString()}
                    </div>
                  )}
                  <a href={d.patch_url} target="_blank" rel="noreferrer"
                    style={{fontSize:12,color:C.green,fontWeight:600,padding:"6px 14px",
                      border:`1px solid ${C.green}40`,borderRadius:6,
                      background:C.green+"10",display:"inline-flex",alignItems:"center",gap:6}}>
                    <NavIcon name="externalLink" size={12} color={C.green}/>
                    View Patch / Advisory
                  </a>
                </div>
              )}

              {/* CVE.org affected products */}
              {cveOrg?.affected?.length>0&&(
                <div style={{marginBottom:18}}>
                  <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:10,
                    textTransform:"uppercase",letterSpacing:"0.06em"}}>
                    Affected Products (CVE.org)
                  </div>
                  <div style={{background:C.surfaceHi,border:`1px solid ${C.border}`,
                    borderRadius:10,overflow:"hidden"}}>
                    {cveOrg.affected.map((a,i)=>(
                      <div key={i} style={{padding:"10px 14px",
                        borderBottom:i<cveOrg.affected.length-1?`1px solid ${C.border}20`:"none",
                        display:"flex",alignItems:"center",gap:8}}>
                        <span style={{fontSize:12,color:C.white||C.textHi,fontWeight:500}}>{a}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Top references preview */}
              {allRefs.length>0&&(
                <div>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                    <div style={{fontSize:10,color:C.muted,fontWeight:600,textTransform:"uppercase",letterSpacing:"0.06em"}}>
                      Key References
                    </div>
                    {allRefs.length>4&&(
                      <button onClick={()=>setTab("references")}
                        style={{fontSize:11,color:C.accentText,background:"none",border:"none",
                          cursor:"pointer",fontFamily:"inherit",fontWeight:600}}>
                        View all {allRefs.length} →
                      </button>
                    )}
                  </div>
                  {allRefs.filter(r=>r.tags?.includes("Patch")||r.tags?.includes("Vendor Advisory")).slice(0,4).map((ref,i)=>(
                    <div key={i} style={{display:"flex",alignItems:"flex-start",gap:8,marginBottom:8,
                      padding:"8px 12px",background:C.surfaceHi,borderRadius:7}}>
                      <div style={{flex:1,minWidth:0}}>
                        <a href={ref.url} target="_blank" rel="noreferrer"
                          style={{fontSize:12,color:C.accentText,wordBreak:"break-all",lineHeight:1.5}}>
                          {ref.url}
                        </a>
                      </div>
                      <div style={{display:"flex",gap:4,flexShrink:0}}>
                        {ref.tags?.slice(0,2).map(t=>(
                          <span key={t} style={{fontSize:9,padding:"1px 6px",borderRadius:3,
                            background:t==="Patch"?C.green+"20":t.includes("Advisory")?C.amber+"20":C.surfaceHi,
                            color:t==="Patch"?C.green:t.includes("Advisory")?C.amber:C.muted,
                            fontWeight:600,whiteSpace:"nowrap"}}>{t}</span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ── CVSS DETAILS TAB ── */}
          {tab==="cvss"&&(
            <div>
              <div style={{fontSize:13,color:C.muted,marginBottom:16,lineHeight:1.6}}>
                The CVSS vector breaks down into 8 metrics that determine exploitability and impact.
                Red = high risk, amber = medium risk, grey = low risk for that metric.
              </div>
              {!cvssMetrics&&<div style={{color:C.muted,fontSize:13}}>No CVSS vector available for this CVE.</div>}
              {cvssMetrics&&(
                <div>
                  {/* Vector string */}
                  <div style={{padding:"10px 14px",background:C.surfaceHi,borderRadius:8,
                    marginBottom:20,fontFamily:"monospace",fontSize:12,color:C.accentText,
                    wordBreak:"break-all",border:`1px solid ${C.border}`}}>
                    {d.cvss_vector||nvd?.cvss?.vector}
                  </div>
                  {/* Metric grid */}
                  <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",gap:10,marginBottom:20}}>
                    {Object.entries(cvssMetrics).filter(([k])=>CVSS_META[k]).map(([key,val])=>{
                      const meta=CVSS_META[key];
                      const valMeta=meta[val];
                      const color=cvssRiskColor(key,val);
                      const bg=cvssRiskBg(key,val);
                      return(
                        <div key={key} style={{padding:"12px 14px",background:bg,
                          border:`1px solid ${color}40`,borderRadius:10}}>
                          <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:6,
                            textTransform:"uppercase",letterSpacing:"0.05em"}}>
                            {meta.label}
                          </div>
                          <div style={{display:"flex",alignItems:"center",gap:6}}>
                            <span style={{fontSize:16,fontWeight:800,color:color,
                              fontFamily:"monospace"}}>{key}:{val}</span>
                            <span style={{fontSize:13,color:color,fontWeight:600}}>
                              {valMeta?.l||val}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  {/* Score breakdown */}
                  <div style={{padding:"16px",background:C.surfaceHi,borderRadius:12,
                    border:`1px solid ${C.border}`}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
                      <span style={{fontSize:13,fontWeight:600,color:C.white||C.textHi}}>Base Score</span>
                      <span style={{fontSize:22,fontWeight:800,color:scoreColor}}>{score}</span>
                    </div>
                    <div style={{height:8,background:C.border,borderRadius:4,overflow:"hidden",marginBottom:6}}>
                      <div style={{height:"100%",borderRadius:4,
                        width:`${(score/10)*100}%`,
                        background:`linear-gradient(90deg,${C.green},${C.amber} 55%,${C.red})`}}/>
                    </div>
                    <div style={{display:"flex",justifyContent:"space-between",fontSize:10,color:C.muted}}>
                      <span>Low (0.1–3.9)</span><span>Medium (4.0–6.9)</span>
                      <span>High (7.0–8.9)</span><span>Critical (9.0–10.0)</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── REFERENCES TAB ── */}
          {tab==="references"&&(
            <div>
              {allRefs.length===0&&<div style={{color:C.muted,fontSize:13}}>No references available.</div>}
              {Object.entries(refsByCategory).map(([cat,refs])=>(
                <div key={cat} style={{marginBottom:20}}>
                  <div style={{fontSize:11,fontWeight:700,color:
                    cat==="Patch"?C.green:cat==="Exploit"?C.red:cat==="Advisory"?C.amber:C.muted,
                    marginBottom:10,textTransform:"uppercase",letterSpacing:"0.06em",
                    display:"flex",alignItems:"center",gap:6}}>
                    <span style={{width:6,height:6,borderRadius:"50%",display:"inline-block",
                      background:cat==="Patch"?C.green:cat==="Exploit"?C.red:cat==="Advisory"?C.amber:C.border}}/>
                    {cat} ({refs.length})
                  </div>
                  {refs.map((ref,i)=>(
                    <div key={i} style={{display:"flex",alignItems:"center",gap:8,
                      padding:"8px 12px",marginBottom:4,
                      background:C.surfaceHi,borderRadius:7,
                      border:`1px solid ${C.border}`}}>
                      <a href={ref.url} target="_blank" rel="noreferrer"
                        style={{flex:1,fontSize:12,color:C.accentText,
                          wordBreak:"break-all",lineHeight:1.5}}>
                        <NavIcon name="externalLink" size={10} color={C.accentText}/>{" "}{ref.url}
                      </a>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}

          {/* ── AFFECTED PACKAGES TAB (OSV) ── */}
          {tab==="packages"&&osv&&(
            <div>
              <div style={{fontSize:12,color:C.muted,marginBottom:16}}>
                Package-level data from OSV (Open Source Vulnerabilities). Shows affected ecosystems and fix versions.
              </div>
              {osv.vulns?.map((v,i)=>(
                <div key={i} style={{background:C.surface,border:`1px solid ${C.border}`,
                  borderRadius:12,padding:"16px 18px",marginBottom:12,boxShadow:C.shadow}}>
                  <div style={{fontSize:13,fontWeight:700,color:C.accentText,marginBottom:10}}>
                    {v.id}
                  </div>
                  {v.packages?.map((p,j)=>(
                    <div key={j} style={{display:"flex",alignItems:"center",gap:10,
                      padding:"8px 12px",background:C.surfaceHi,borderRadius:7,marginBottom:6}}>
                      <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,
                        background:C.accentDim,color:C.accentText,fontWeight:700}}>
                        {p.ecosystem}
                      </span>
                      <span style={{fontSize:13,color:C.white||C.textHi,fontWeight:500}}>{p.name}</span>
                      {p.fix&&(
                        <span style={{marginLeft:"auto",fontSize:11,color:C.green,fontWeight:700}}>
                          Fix: {p.fix}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}

          {/* ── ALL SOURCES TAB ── */}
          {tab==="sources"&&(
            <div>
              {loading&&<div style={{textAlign:"center",padding:40,color:C.muted}}>
                Loading data from all sources...
              </div>}
              {!loading&&enriched?.sources?.map(src=>(
                <div key={src.source} style={{background:C.surface,border:`1px solid ${
                  src.status==="ok"?C.border:C.border+"50"}`,borderRadius:12,
                  padding:"16px 18px",marginBottom:12,opacity:src.status==="ok"?1:0.6,
                  boxShadow:C.shadow}}>
                  <div style={{display:"flex",justifyContent:"space-between",
                    alignItems:"center",marginBottom:src.status==="ok"?12:0}}>
                    <span style={{fontSize:14,fontWeight:700,color:C.white||C.textHi}}>
                      {src.source}
                    </span>
                    <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:600,
                      background:src.status==="ok"?C.green+"20":C.muted+"20",
                      color:src.status==="ok"?C.green:C.muted}}>
                      {src.status==="ok"?"Found":src.status==="not_found"?"Not in database":"Error"}
                    </span>
                  </div>
                  {src.status==="ok"&&src.source==="NVD"&&src.cvss&&(
                    <div style={{display:"flex",gap:10,flexWrap:"wrap",marginBottom:8}}>
                      <span style={{fontSize:12,fontWeight:700,
                        color:(SEV_COLORS=>{return SEV_COLORS[src.cvss.severity]||C.muted;})({CRITICAL:C.red,HIGH:C.amber,MEDIUM:C.purple,LOW:C.green})
                      }}>CVSS {src.cvss.version}: {src.cvss.score} {src.cvss.severity}</span>
                      {src.weaknesses?.map(w=>(
                        <span key={w} style={{fontSize:11,padding:"2px 8px",borderRadius:4,
                          background:C.purple+"20",color:C.purple}}>{w}</span>
                      ))}
                    </div>
                  )}
                  {src.status==="ok"&&src.source==="CVE.org"&&(
                    <div>
                      <div style={{fontSize:11,color:C.muted,marginBottom:4}}>
                        State: <span style={{color:C.accentText,fontWeight:600}}>{src.state}</span>
                        {src.published&&<span style={{marginLeft:10}}>Published: {src.published}</span>}
                      </div>
                      {src.affected?.slice(0,3).map((a,i)=>(
                        <div key={i} style={{fontSize:11,color:C.text,padding:"3px 0"}}>→ {a}</div>
                      ))}
                    </div>
                  )}
                  {src.status==="ok"&&src.source==="CVE Trends"&&(
                    <div style={{fontSize:12,color:src.trending?C.accentText:C.muted}}>
                      {src.trending?"📈 Currently trending":"Not trending"}
                      {src.count_24h>0&&<span style={{marginLeft:8,color:C.muted}}>{src.count_24h} mentions/24h</span>}
                    </div>
                  )}
                  {src.status==="error"&&(
                    <div style={{fontSize:11,color:C.red}}>{src.error||"Failed to fetch"}</div>
                  )}
                  {src.url&&src.status==="ok"&&(
                    <a href={src.url} target="_blank" rel="noreferrer"
                      style={{fontSize:11,color:C.accentText,marginTop:8,
                        display:"flex",alignItems:"center",gap:4}}>
                      <NavIcon name="externalLink" size={10} color={C.accentText}/>View on {src.source}
                    </a>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── ASSET MANAGER ─────────────────────────────────────────────────────────────
function RelGraph({iocId,iocValue,token,C}){
  const [rels,setRels]=useState([]); const [pos,setPos]=useState({});
  const [dragging,setDragging]=useState(null); const [newRelTarget,setNewRelTarget]=useState(""); const [newRelType,setNewRelType]=useState("related_to");
  const [allIocs,setAllIocs]=useState([]); const svgRef=useRef(null); const animRef=useRef(null);

  useEffect(()=>{
    api(`/iocs/${encodeURIComponent(iocId)}/relationships`,{},token).then(r=>r.ok?r.json():[]).then(setRels);
    api("/iocs",{},token).then(r=>r.ok?r.json():[]).then(setAllIocs);
  },[iocId,token]);

  const nodes={}; nodes[iocId]={id:iocId,value:iocValue,isCenter:true};
  rels.forEach(r=>{
    if(!nodes[r.source_id])nodes[r.source_id]={id:r.source_id,value:r.source_defanged||r.source_value,type:r.source_type};
    if(!nodes[r.target_id])nodes[r.target_id]={id:r.target_id,value:r.target_defanged||r.target_value,type:r.target_type};
  });
  const nodeList=Object.values(nodes);
  const linkList=rels.map(r=>({id:r.id,source:r.source_id,target:r.target_id,type:r.relationship_type}));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(()=>{setPos(p=>{const next={...p};nodeList.forEach((n,i)=>{if(!next[n.id]){const angle=(i/Math.max(nodeList.length,1))*Math.PI*2;next[n.id]=n.isCenter?{x:300,y:190}:{x:300+Math.cos(angle)*130,y:190+Math.sin(angle)*100};}});return next;});},[rels]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(()=>{
    if(nodeList.length<2){clearInterval(animRef.current);return;}
    animRef.current=setInterval(()=>{
      setPos(prev=>{
        const next={};nodeList.forEach(n=>{next[n.id]={...prev[n.id]||{x:300,y:190}};});
        for(let i=0;i<nodeList.length;i++){for(let j=i+1;j<nodeList.length;j++){const a=nodeList[i].id,b=nodeList[j].id;if(!next[a]||!next[b])continue;const dx=next[b].x-next[a].x,dy=next[b].y-next[a].y;const dist=Math.sqrt(dx*dx+dy*dy)||1;const f=3000/(dist*dist);next[a]={x:next[a].x-(dx/dist)*f*0.1,y:next[a].y-(dy/dist)*f*0.1};next[b]={x:next[b].x+(dx/dist)*f*0.1,y:next[b].y+(dy/dist)*f*0.1};}}
        linkList.forEach(link=>{const a=link.source,b=link.target;if(!next[a]||!next[b])return;const dx=next[b].x-next[a].x,dy=next[b].y-next[a].y;const dist=Math.sqrt(dx*dx+dy*dy)||1;const f=(dist-140)*0.04;next[a]={x:next[a].x+(dx/dist)*f,y:next[a].y+(dy/dist)*f};next[b]={x:next[b].x-(dx/dist)*f,y:next[b].y-(dy/dist)*f};});
        nodeList.forEach(n=>{if(!next[n.id])return;next[n.id]={x:next[n.id].x+(300-next[n.id].x)*0.008,y:next[n.id].y+(190-next[n.id].y)*0.008};});
        return next;
      });
    },50);
    return()=>clearInterval(animRef.current);
  },[rels]); // eslint-disable-line react-hooks/exhaustive-deps

  function startDrag(e,nodeId){e.preventDefault();setDragging(nodeId);clearInterval(animRef.current);}
  function onMove(e){if(!dragging||!svgRef.current)return;const rect=svgRef.current.getBoundingClientRect();setPos(p=>({...p,[dragging]:{x:e.clientX-rect.left,y:e.clientY-rect.top}}));}
  function stopDrag(){setDragging(null);}

  async function addRel(){
    if(!newRelTarget)return;
    await api(`/iocs/${encodeURIComponent(iocId)}/relationships`,{method:"POST",body:JSON.stringify({target_id:newRelTarget,relationship_type:newRelType})},token);
    api(`/iocs/${encodeURIComponent(iocId)}/relationships`,{},token).then(r=>r.ok?r.json():[]).then(setRels);
    setNewRelTarget("");
  }
  async function deleteRel(relId){
    await api(`/iocs/relationships/${relId}`,{method:"DELETE"},token);
    setRels(p=>p.filter(r=>r.id!==relId));
  }

  return(
    <div>
      <div style={{display:"flex",gap:8,marginBottom:16,flexWrap:"wrap",alignItems:"flex-end"}}>
        <div style={{flex:1,minWidth:180}}>
          <label style={{display:"block",fontSize:11,color:C.muted,marginBottom:4,fontWeight:600}}>Link to IOC</label>
          <select value={newRelTarget} onChange={e=>setNewRelTarget(e.target.value)} style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"8px 10px",borderRadius:6,fontSize:12,outline:"none",fontFamily:"inherit"}}>
            <option value="">Select IOC...</option>
            {allIocs.filter(i=>i.id!==iocId).map(i=><option key={i.id} value={i.id}>{i.type}: {(i.value_defanged||i.value)?.slice(0,40)}</option>)}
          </select>
        </div>
        <div>
          <label style={{display:"block",fontSize:11,color:C.muted,marginBottom:4,fontWeight:600}}>Relationship</label>
          <select value={newRelType} onChange={e=>setNewRelType(e.target.value)} style={{background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"8px 10px",borderRadius:6,fontSize:12,outline:"none",fontFamily:"inherit"}}>
            {REL_TYPES.map(t=><option key={t}>{t}</option>)}
          </select>
        </div>
        <Btn onClick={addRel} disabled={!newRelTarget} C={C} sm>Link</Btn>
      </div>
      {nodeList.length<=1?(
        <div style={{textAlign:"center",padding:32,color:C.muted,fontSize:13,background:C.surfaceHi,borderRadius:8}}>No relationships yet. Link this IOC to others above.</div>
      ):(
        <svg ref={svgRef} width="600" height="380" style={{width:"100%",background:C.surfaceHi,borderRadius:10,cursor:dragging?"grabbing":"default"}}
          onMouseMove={onMove} onMouseUp={stopDrag} onMouseLeave={stopDrag}>
          <defs><marker id="arr" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L0,6 L6,3 z" fill={C.border}/></marker></defs>
          {linkList.map(link=>{const a=pos[link.source],b=pos[link.target];if(!a||!b)return null;const mx=(a.x+b.x)/2,my=(a.y+b.y)/2;return(<g key={link.id}><line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={C.border} strokeWidth={1.5} markerEnd="url(#arr)"/><text x={mx} y={my-6} textAnchor="middle" fill={C.muted} fontSize={9} fontFamily="inherit">{link.type}</text><circle cx={mx} cy={my} r={6} fill={C.red+"20"} stroke={C.red+"40"} strokeWidth={1} style={{cursor:"pointer"}} onClick={()=>deleteRel(link.id)}/><text x={mx} y={my+4} textAnchor="middle" fill={C.red} fontSize={8} style={{cursor:"pointer"}} onClick={()=>deleteRel(link.id)}>×</text></g>);})}
          {nodeList.map(node=>{const p=pos[node.id];if(!p)return null;const isCenter=node.isCenter;return(<g key={node.id} transform={`translate(${p.x},${p.y})`} style={{cursor:"grab"}} onMouseDown={e=>startDrag(e,node.id)}><circle r={isCenter?26:20} fill={isCenter?C.accentDim:C.surfaceHi} stroke={isCenter?C.accent:C.border} strokeWidth={isCenter?2:1.5}/><text textAnchor="middle" y={-8} fill={C.accentText} fontSize={8} fontFamily="inherit" fontWeight={700}>{node.type||"IOC"}</text><text textAnchor="middle" y={4} fill={C.white} fontSize={8} fontFamily="inherit">{(node.value||"")?.slice(0,16)}</text>{(node.value||"").length>16&&<text textAnchor="middle" y={13} fill={C.muted} fontSize={7}>...</text>}</g>);})}
        </svg>
      )}
    </div>
  );
}

// ── ENRICHMENT PANEL ──────────────────────────────────────────────────────────

function EnrichmentPanel({ioc,token,onClose,C,me}){
  const [data,setData]=useState(ioc.enrichment||null); const [loading,setLoading]=useState(false);
  const [notes,setNotes]=useState([]); const [newNote,setNewNote]=useState("");
  const [history,setHistory]=useState([]); const [tab,setTab]=useState("enrichment");
  const [fpReason,setFpReason]=useState(ioc.fp_reason||""); const [isFP,setIsFP]=useState(ioc.false_positive||false);
  const [subnetData,setSubnetData]=useState(null);

  useEffect(()=>{
    api(`/iocs/${encodeURIComponent(ioc.id)}/notes`,{},token).then(r=>r.ok?r.json():[]).then(setNotes);
    api(`/iocs/${encodeURIComponent(ioc.id)}/score-history`,{},token).then(r=>r.ok?r.json():[]).then(setHistory);
  },[ioc.id,token]);

  async function reEnrich(){setLoading(true);const r=await api(`/iocs/${encodeURIComponent(ioc.id)}/re-enrich`,{method:"POST"},token);if(r.ok){const d=await r.json();setData(d.enrichment);}setLoading(false);}
  async function addNote(){if(!newNote.trim())return;await api(`/iocs/${encodeURIComponent(ioc.id)}/notes`,{method:"POST",body:JSON.stringify({note:newNote})},token);setNewNote("");api(`/iocs/${encodeURIComponent(ioc.id)}/notes`,{},token).then(r=>r.ok?r.json():[]).then(setNotes);}
  async function deleteNote(noteId){await api(`/iocs/${encodeURIComponent(ioc.id)}/notes/${noteId}`,{method:"DELETE"},token);setNotes(p=>p.filter(n=>n.id!==noteId));}
  async function toggleFP(){const newFP=!isFP;await api(`/iocs/${encodeURIComponent(ioc.id)}/false-positive`,{method:"PATCH",body:JSON.stringify({false_positive:newFP,reason:fpReason})},token);setIsFP(newFP);}
  async function pivotSubnet(){const r=await api(`/iocs/pivot/subnet/${ioc.value}`,{},token);if(r.ok)setSubnetData(await r.json());setTab("subnet");}

  const vt=data?.virustotal||{};const abuse=data?.abuseipdb||{};const uh=data?.urlhaus||{};
  const TABS=[{id:"enrichment",label:"Enrichment"},{id:"notes",label:`Notes (${notes.length})`},{id:"history",label:"Score History"},{id:"relations",label:"Relationships"},{id:"fp",label:"False Positive"},...(ioc.type==="IPv4"?[{id:"subnet",label:"Subnet Pivot"}]:[])];

  return(
    <div style={{position:"fixed",inset:0,background:"#00000090",display:"flex",alignItems:"center",justifyContent:"center",zIndex:500,padding:16}} onClick={onClose}>
      <div onClick={e=>e.stopPropagation()} style={{width:"100%",maxWidth:680,maxHeight:"92vh",overflowY:"auto",background:C.surface,border:`1px solid ${C.border}`,borderRadius:16,boxShadow:C.shadow,fontFamily:C.font||"inherit"}}>
        <div style={{padding:"20px 24px 0",borderBottom:`1px solid ${C.border}`}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:12}}>
            <div style={{flex:1,marginRight:12}}>
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6,flexWrap:"wrap"}}>
                <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,background:C.badge,color:C.accentText,fontWeight:700}}>{ioc.type}</span>
                <TLPBadge level={ioc.tlp}/>
                {isFP&&<span style={{fontSize:11,padding:"2px 8px",borderRadius:4,background:C.amber+"20",color:C.amber,fontWeight:700}}>FALSE POSITIVE</span>}
              </div>
              <div style={{fontSize:15,fontWeight:700,color:C.white,wordBreak:"break-all"}}>{ioc.value_defanged||ioc.value}</div>
              <div style={{fontSize:12,color:C.muted,marginTop:4}}>{ioc.industry} · {ioc.author||"unknown"}</div>
            </div>
            <div style={{display:"flex",gap:8,flexShrink:0}}>
              <button onClick={reEnrich} disabled={loading} style={{padding:"6px 14px",background:C.accentDim,border:`1px solid ${C.accent}40`,color:C.accentText,borderRadius:6,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600}}>{loading?"...":"↻ Re-enrich"}</button>
              <button onClick={onClose} style={{background:"none",border:"none",color:C.muted,fontSize:22,cursor:"pointer",padding:0}}>×</button>
            </div>
          </div>
          <div style={{display:"flex",gap:1,overflowX:"auto"}}>
            {TABS.map(t=><button key={t.id} onClick={()=>setTab(t.id)} style={{padding:"9px 16px",border:"none",cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:500,background:"transparent",color:tab===t.id?C.accentText:C.muted,borderBottom:`2px solid ${tab===t.id?C.accentText:"transparent"}`,whiteSpace:"nowrap"}}>{t.label}</button>)}
          </div>
        </div>
        <div style={{padding:24}}>
          {tab==="enrichment"&&(
            <>
              {!data&&<div style={{color:C.muted,fontSize:13}}>No enrichment data. Click Re-enrich.</div>}
              {data&&(<>
                <div style={{background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:10,padding:18,marginBottom:16}}>
                  <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:.5,marginBottom:12,textTransform:"uppercase"}}>Confidence Score</div>
                  <div style={{display:"flex",alignItems:"center",gap:16,marginBottom:12}}>
                    <div style={{fontSize:48,fontWeight:700,color:data.calculated_confidence>=80?C.green:data.calculated_confidence>=50?C.amber:C.red,lineHeight:1}}>{data.calculated_confidence}</div>
                    <div style={{flex:1}}>
                      <div style={{height:8,background:C.border,borderRadius:4,overflow:"hidden",marginBottom:10}}>
                        <div style={{width:`${data.calculated_confidence}%`,height:"100%",borderRadius:4,background:data.calculated_confidence>=80?C.green:data.calculated_confidence>=50?C.amber:C.red,transition:"width .5s"}}/>
                      </div>
                      {data.confidence_reasons?.map((r,i)=><div key={i} style={{fontSize:11,color:C.muted,marginBottom:3,display:"flex",gap:6}}><span style={{color:C.accentText}}>›</span>{r}</div>)}
                    </div>
                  </div>
                  <div style={{fontSize:11,color:C.muted}}>Enriched: {data.enriched_at?new Date(data.enriched_at).toLocaleString():"?"} · Cached 24h</div>
                </div>
                {[{key:"virustotal",label:"VIRUSTOTAL",d:vt,fields:[["VT Score",`${vt.vt_score??0}%`],["Malicious",`${vt.malicious??0}/${vt.total??0}`],vt.country&&["Country",vt.country],vt.asn&&["ASN",vt.asn]]},
                  {key:"abuseipdb",label:"ABUSEIPDB",d:abuse,fields:[["Abuse Score",`${abuse.abuse_score??0}/100`],["Reports",`${abuse.total_reports??0}`],abuse.country&&["Country",abuse.country],abuse.isp&&["ISP",abuse.isp]]},
                  {key:"urlhaus",label:"URLHAUS",d:uh,fields:[uh.threat&&["Threat",uh.threat],uh.url_status&&["Status",uh.url_status]]},
                ].map(({key,label,d,fields})=>{
                  if(!d||d.skipped)return null;
                  return(<div key={key} style={{background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:10,padding:16,marginBottom:10}}>
                    <div style={{fontSize:11,color:C.accentText,fontWeight:700,letterSpacing:.5,marginBottom:12}}>{label}</div>
                    {d.error?<div style={{fontSize:12,color:C.red}}>{d.error}</div>:d.found===false?<div style={{fontSize:12,color:C.muted}}>Not found in {label}</div>:
                      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(120px,1fr))",gap:12}}>
                        {fields.filter(Boolean).map(([k,v])=><div key={k}><div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:2}}>{k}</div><div style={{fontSize:13,color:C.white,fontWeight:500}}>{v}</div></div>)}
                      </div>}
                    {d.link&&<a href={d.link} target="_blank" rel="noreferrer" style={{fontSize:11,color:C.accentText,display:"inline-block",marginTop:10,fontWeight:600}}>View on {label} →</a>}
                  </div>);
                })}
                {ioc.mitre_techniques?.length>0&&<div style={{marginTop:12}}><div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:8,textTransform:"uppercase"}}>MITRE ATT&CK</div><div style={{display:"flex",flexWrap:"wrap",gap:6}}>{ioc.mitre_techniques.map(t=><span key={t} style={{fontSize:11,padding:"3px 10px",borderRadius:4,background:C.purple+"20",color:C.purple,fontWeight:600,border:`1px solid ${C.purple}40`}}>{t}</span>)}</div></div>}
              </>)}
            </>
          )}
          {tab==="notes"&&(
            <>
              <div style={{display:"flex",gap:8,marginBottom:16}}>
                <input value={newNote} onChange={e=>setNewNote(e.target.value)} onKeyDown={e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();addNote();}}} placeholder="Add investigation note... (Enter to submit)"
                  style={{flex:1,background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"10px 14px",borderRadius:8,fontSize:13,outline:"none",fontFamily:"inherit"}}/>
                <Btn onClick={addNote} disabled={!newNote.trim()} C={C}>Add</Btn>
              </div>
              {notes.length===0&&<div style={{fontSize:13,color:C.muted,textAlign:"center",padding:24}}>No notes yet.</div>}
              {notes.map(n=>(
                <div key={n.id} style={{background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:10,padding:14,marginBottom:10}}>
                  <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                    <div style={{display:"flex",gap:10}}><span style={{fontSize:12,color:C.accentText,fontWeight:700}}>{n.username}</span><span style={{fontSize:11,color:C.muted}}>{new Date(n.created_at).toLocaleString()}</span></div>
                    {(me?.role==="admin"||n.user_id===me?.id)&&<button onClick={()=>deleteNote(n.id)} style={{background:"none",border:"none",color:C.red,cursor:"pointer",fontSize:16,padding:0,opacity:.7}}>×</button>}
                  </div>
                  <div style={{fontSize:13,color:C.text,lineHeight:1.6,whiteSpace:"pre-wrap"}}>{n.note}</div>
                </div>
              ))}
            </>
          )}
          {tab==="history"&&(
            <>
              {history.length===0&&<div style={{fontSize:13,color:C.muted,textAlign:"center",padding:24}}>No score history yet.</div>}
              {history.map(h=>(
                <div key={h.id} style={{background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:10,padding:14,marginBottom:10}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                    <div style={{display:"flex",alignItems:"center",gap:12}}>
                      <span style={{fontSize:20,color:C.muted,textDecoration:"line-through"}}>{h.old_score}</span>
                      <span style={{fontSize:12,color:C.muted}}>→</span>
                      <span style={{fontSize:28,fontWeight:700,color:h.new_score>=80?C.green:h.new_score>=50?C.amber:C.red}}>{h.new_score}</span>
                      <span style={{fontSize:12,padding:"2px 8px",borderRadius:4,fontWeight:700,background:h.delta>0?C.green+"20":h.delta<0?C.red+"20":C.border,color:h.delta>0?C.green:h.delta<0?C.red:C.muted}}>{h.delta>0?"+":""}{h.delta}</span>
                    </div>
                    <div style={{fontSize:11,color:C.muted,textAlign:"right"}}><div style={{fontWeight:600}}>{h.triggered_by}</div><div>{new Date(h.created_at).toLocaleString()}</div></div>
                  </div>
                  {h.reason&&h.reason.split(" | ").map((r,j)=><div key={j} style={{fontSize:11,color:C.muted,marginBottom:2,display:"flex",gap:6}}><span style={{color:C.accentText}}>›</span>{r}</div>)}
                </div>
              ))}
            </>
          )}
          {tab==="relations"&&<RelGraph iocId={ioc.id} iocValue={ioc.value_defanged||ioc.value} token={token} C={C}/>}
          {tab==="fp"&&(
            <div style={{padding:4}}>
              <div style={{marginBottom:16,padding:14,background:isFP?C.amber+"10":C.surfaceHi,border:`1px solid ${isFP?C.amber+"40":C.border}`,borderRadius:10}}>
                <div style={{fontSize:13,color:isFP?C.amber:C.text,fontWeight:700,marginBottom:8}}>{isFP?"⚠ Marked as False Positive":"Mark as False Positive"}</div>
                <div style={{fontSize:12,color:C.muted,marginBottom:12,lineHeight:1.6}}>False positives are excluded from TAXII and STIX exports but kept in the database.</div>
                <Field label="Reason" C={C}><input value={fpReason} onChange={e=>setFpReason(e.target.value)} placeholder="Why is this a false positive?" style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"10px 14px",borderRadius:8,fontSize:13,outline:"none",boxSizing:"border-box",fontFamily:"inherit"}}/></Field>
                <Btn onClick={toggleFP} variant={isFP?"ghost":"danger"} C={C}>{isFP?"Remove FP Flag":"Flag as False Positive"}</Btn>
              </div>
            </div>
          )}
          {tab==="subnet"&&(
            <>
              {!subnetData&&<div style={{textAlign:"center",padding:32}}><div style={{fontSize:13,color:C.muted,marginBottom:16}}>Find all IOCs in the same /24 subnet as {ioc.value}</div><Btn onClick={pivotSubnet} C={C}>Search Subnet</Btn></div>}
              {subnetData&&(<>
                <div style={{fontSize:13,marginBottom:14}}><span style={{color:C.accentText,fontWeight:700}}>{subnetData.subnet}</span> — <span style={{color:C.muted}}>{subnetData.count} IOC{subnetData.count!==1?"s":""} found</span></div>
                {subnetData.iocs?.map(s=>(
                  <div key={s.id} style={{background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:8,padding:12,marginBottom:8,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                    <div><div style={{fontSize:13,color:C.white,fontWeight:500}}>{s.value_defanged||s.value}</div><div style={{fontSize:11,color:C.muted,marginTop:2}}>{s.industry} · conf {s.confidence}</div></div>
                    <TLPBadge level={s.tlp}/>
                  </div>
                ))}
              </>)}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ── PUBLIC SEARCH ─────────────────────────────────────────────────────────────
function PublicSearch({C}){
  const [query,setQuery]=useState(""); const [result,setResult]=useState(null); const [loading,setLoading]=useState(false);
  async function search(){if(!query.trim())return;setLoading(true);setResult(null);const r=await fetch(`${API_BASE}/public/search?q=${encodeURIComponent(query)}`);if(r.ok)setResult(await r.json());setLoading(false);}
  const verdictColor={MALICIOUS:C.red,SUSPICIOUS:C.amber,CLEAN:C.green}[result?.verdict]||C.muted;
  const vt=result?.enrichment?.virustotal||{};const abuse=result?.enrichment?.abuseipdb||{};const uh=result?.enrichment?.urlhaus||{};
  return(
    <div style={{maxWidth:700,margin:"0 auto"}}>
      <div style={{textAlign:"center",marginBottom:32}}>
        <div style={{fontSize:20,fontWeight:700,color:C.white,marginBottom:8}}>Public IOC Lookup</div>
        <div style={{fontSize:13,color:C.muted}}>Check any IP, domain, URL or hash. DB-first — if not found, queries providers and auto-adds if malicious.</div>
      </div>
      <div style={{display:"flex",gap:10,marginBottom:24}}>
        <input value={query} onChange={e=>setQuery(e.target.value)} onKeyDown={e=>{if(e.key==="Enter")search();}} placeholder="Enter IP, domain, URL, MD5, SHA256..."
          style={{flex:1,background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"14px 18px",borderRadius:10,fontSize:15,outline:"none",fontFamily:"inherit"}}/>
        <button onClick={search} disabled={loading||!query.trim()} style={{padding:"14px 24px",background:C.accent,border:"none",color:"#fff",borderRadius:10,cursor:"pointer",fontSize:15,fontWeight:700,fontFamily:"inherit",opacity:loading?0.5:1}}>{loading?"Checking...":"Search"}</button>
      </div>
      {result&&(
        <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,overflow:"hidden",boxShadow:C.shadow}}>
          <div style={{padding:"16px 20px",background:verdictColor+"15",borderBottom:`1px solid ${verdictColor}30`,display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:12}}>
            <div>
              <div style={{fontSize:12,color:C.muted,fontWeight:600,marginBottom:4}}>
                {result.found_in_db?"✓ Found in ThreatFeed database":"Checked via external providers"}
                {result.auto_added&&<span style={{marginLeft:8,fontSize:11,color:C.amber,background:C.amber+"20",padding:"1px 6px",borderRadius:3,fontWeight:700}}>AUTO-ADDED TO DB</span>}
              </div>
              <div style={{fontSize:15,fontWeight:700,color:C.white}}>{result.value}</div>
              <div style={{fontSize:12,color:C.muted,marginTop:2}}>{result.ioc_type}</div>
            </div>
            <div style={{textAlign:"right"}}>
              <div style={{fontSize:28,fontWeight:700,color:verdictColor}}>{result.verdict||"—"}</div>
              <div style={{fontSize:12,color:C.muted}}>Confidence: {result.confidence}</div>
              {result.found_in_db&&result.last_updated&&<div style={{fontSize:11,color:C.muted}}>Last updated: {new Date(result.last_updated).toLocaleDateString()}</div>}
            </div>
          </div>
          <div style={{padding:20}}>
            {result.found_in_db&&<div style={{marginBottom:16,display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(130px,1fr))",gap:12}}>{[["Industry",result.industry],["TLP",result.tlp],["Added by",result.added_by],["Tags",(result.tags||[]).join(", ")||"none"]].map(([k,v])=><div key={k}><div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:2}}>{k}</div><div style={{fontSize:13,color:C.text,fontWeight:500}}>{v||"—"}</div></div>)}{result.description&&<div style={{gridColumn:"1/-1"}}><div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:2}}>Description</div><div style={{fontSize:13,color:C.text,lineHeight:1.6}}>{result.description}</div></div>}</div>}
            {result.reasons?.length>0&&<div style={{marginBottom:16}}><div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:8,textTransform:"uppercase"}}>Why this verdict</div>{result.reasons.map((r,i)=><div key={i} style={{fontSize:12,color:C.text,marginBottom:4,display:"flex",gap:6}}><span style={{color:C.accentText}}>›</span>{r}</div>)}</div>}
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:12}}>
              {[{label:"VirusTotal",d:vt,score:vt.vt_score,detail:`${vt.malicious??0}/${vt.total??0} engines`},{label:"AbuseIPDB",d:abuse,score:abuse.abuse_score,detail:`${abuse.total_reports??0} reports`},{label:"URLhaus",d:uh,score:uh.found===true?85:uh.found===false?0:null,detail:uh.found===true?uh.threat||"Found":uh.found===false?"Not found":"N/A"}].map(({label,d,score,detail})=>{
                if(!d||d.skipped||d.note)return null;
                const color=(score||0)>=50?C.red:(score||0)>=20?C.amber:C.green;
                return(<div key={label} style={{background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:8,padding:14}}>
                  <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:8}}>{label}</div>
                  {d.error?<div style={{fontSize:12,color:C.red}}>{d.error}</div>:(
                    <>{score!=null&&<div style={{fontSize:22,fontWeight:700,color}}>{score}{label!=="URLhaus"?"%":""}</div>}<div style={{fontSize:11,color:C.muted,marginTop:4}}>{detail}</div>{d.link&&<a href={d.link} target="_blank" rel="noreferrer" style={{fontSize:11,color:C.accentText,display:"block",marginTop:8,fontWeight:600}}>View →</a>}</>
                  )}
                </div>);
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── GEO MAP ───────────────────────────────────────────────────────────────────


function AssetManager({token,C,onChanged}){
  const [assets,setAssets]=useState([]);
  const [form,setForm]=useState({name:"",vendor:"",version:"",asset_type:"application"});
  const [suggested,setSuggested]=useState({}); // tracks which fields were auto-filled
  const [autofilling,setAutofilling]=useState(false);
  const [autofillNote,setAutofillNote]=useState("");
  const [saving,setSaving]=useState(false);
  const [msg,setMsg]=useState(""); const [err,setErr]=useState("");
  const debounceRef=useRef(null);

  const ASSET_TYPES=[
    {val:"application",  label:"Application"},
    {val:"os",           label:"Operating System"},
    {val:"hardware",     label:"Hardware / Network"},
    {val:"firmware",     label:"Firmware"},
    {val:"cloud_service",label:"Cloud Service"},
    {val:"library",      label:"Library / SDK"},
    {val:"database",     label:"Database"},
  ];

  const load=useCallback(()=>api("/assets",{},token).then(r=>r.ok?r.json():[]).then(setAssets),[token]);
  useEffect(()=>{load();},[load]);

  // Auto-fill when name changes — debounced 600ms
  function handleNameChange(val){
    setForm(p=>({...p,name:val}));
    setSuggested({});setAutofillNote("");
    if(debounceRef.current) clearTimeout(debounceRef.current);
    if(val.trim().length<2) return;
    debounceRef.current=setTimeout(()=>doAutofill(val),600);
  }

  async function doAutofill(name){
    setAutofilling(true);
    try{
      const r=await api(`/assets/autofill?name=${encodeURIComponent(name)}`,{},token);
      if(!r.ok){setAutofilling(false);return;}
      const d=await r.json();
      if(!d.found){setAutofilling(false);return;}
      const newSuggested={};
      setForm(prev=>{
        const next={...prev};
        // Only fill if field is currently empty
        if(!prev.vendor&&d.vendor){next.vendor=d.vendor;newSuggested.vendor=true;}
        if(!prev.version&&d.version){next.version=d.version;newSuggested.version=true;}
        if(prev.asset_type==="application"&&d.asset_type!=="application"){
          next.asset_type=d.asset_type;newSuggested.asset_type=true;
        }
        return next;
      });
      setSuggested(newSuggested);
      if(d.notes) setAutofillNote(d.notes);
    }catch(e){}
    setAutofilling(false);
  }

  function clearSuggested(field){
    setSuggested(p=>({...p,[field]:false}));
  }

  async function addAsset(){
    if(!form.name.trim())return;
    setSaving(true);setMsg("");setErr("");
    try{
      const r=await api("/assets",{method:"POST",
        body:JSON.stringify({...form,cpe:"",criticality:"high",description:""})},token);
      if(r.ok){
        setMsg(`✓ "${form.name}" added and queued for CVE monitoring.`);
        setForm({name:"",vendor:"",version:"",asset_type:"application"});
        setSuggested({});setAutofillNote("");
        load();if(onChanged)onChanged();
      }else{
        const e=await r.json();
        setErr(`Failed: ${e.detail||r.status}`);
      }
    }catch(e){setErr("Cannot reach server — is the backend running?");}
    setSaving(false);
  }

  // Suggested field wrapper — shows teal dot + "suggested" label + edit clears suggestion
  const SuggestedField=({field,label,children})=>(
    <Field label={
      <div style={{display:"flex",alignItems:"center",gap:6}}>
        <span>{label}</span>
        {suggested[field]&&(
          <span style={{fontSize:10,padding:"1px 6px",borderRadius:3,
            background:C.accent+"20",color:C.accentText,fontWeight:700,
            letterSpacing:"0.03em"}}>
            ✦ auto-filled
          </span>
        )}
      </div>
    } C={C}>
      {children}
    </Field>
  );

  return(
    <div style={{maxWidth:800}}>
      <Card C={C} style={{marginBottom:24}}>
        <div style={{fontSize:14,fontWeight:700,color:C.white||C.textHi,marginBottom:4}}>
          Add Software / Service to Monitor
        </div>
        <div style={{fontSize:12,color:C.muted,marginBottom:20,lineHeight:1.6}}>
          Type a product name — vendor, type, and version are filled automatically.
          {" "}<span style={{color:C.amber,fontWeight:500}}>
            Version defaults to latest−1 (the version before current release).
          </span>
          {" "}Override any field freely.
        </div>

        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14,marginBottom:4}}>
          {/* Name — triggers autofill */}
          <Field label={
            <div style={{display:"flex",alignItems:"center",gap:8}}>
              <span>Product / Software Name *</span>
              {autofilling&&<span style={{fontSize:10,color:C.accentText,fontWeight:600}}>
                looking up...
              </span>}
            </div>
          } C={C}>
            <Inp value={form.name} onChange={handleNameChange}
              placeholder="e.g. Chrome, Cisco Catalyst, Windows 11, OpenSSL" C={C}/>
          </Field>

          <SuggestedField field="vendor" label="Vendor">
            <Inp value={form.vendor} onChange={v=>{setForm(p=>({...p,vendor:v}));clearSuggested("vendor");}}
              placeholder="e.g. Google, Cisco, Microsoft" C={C}/>
          </SuggestedField>

          <SuggestedField field="version" label="Installed Version">
            <Inp value={form.version}
              onChange={v=>{setForm(p=>({...p,version:v}));clearSuggested("version");}}
              placeholder="e.g. 124.0.6367.60 — auto-filled with latest−1" C={C}/>
          </SuggestedField>

          <SuggestedField field="asset_type" label="Type">
            <select value={form.asset_type}
              onChange={e=>{setForm(p=>({...p,asset_type:e.target.value}));clearSuggested("asset_type");}}
              style={{width:"100%",background:C.inputBg,border:`1px solid ${
                suggested.asset_type?C.accent:C.inputBorder}`,
                color:C.inputText,padding:"10px 12px",borderRadius:8,fontSize:14,
                outline:"none",fontFamily:"inherit",
                boxShadow:suggested.asset_type?`0 0 0 2px ${C.accent}20`:"none"}}>
              {ASSET_TYPES.map(t=><option key={t.val} value={t.val}>{t.label}</option>)}
            </select>
          </SuggestedField>
        </div>

        {/* Auto-fill note (e.g. "Log4Shell — CRITICAL" or "EOL") */}
        {autofillNote&&(
          <div style={{marginBottom:12,padding:"8px 14px",background:C.amber+"12",
            border:`1px solid ${C.amber}40`,borderRadius:7,fontSize:12,color:C.amber,
            display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <span>ℹ {autofillNote}</span>
            <button onClick={()=>setAutofillNote("")}
              style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:16,padding:0}}>×</button>
          </div>
        )}

        {err&&<div style={{fontSize:12,color:C.red,margin:"10px 0",padding:"10px 14px",
          background:C.red+"10",borderRadius:6,border:`1px solid ${C.red}30`}}>{err}</div>}
        {msg&&<div style={{fontSize:12,color:C.green,margin:"10px 0",padding:"10px 14px",
          background:C.green+"10",borderRadius:6,border:`1px solid ${C.green}30`}}>{msg}</div>}

        <Btn onClick={addAsset} disabled={!form.name.trim()||saving} C={C}>
          {saving?"Adding...":"Add to Monitor List"}
        </Btn>
      </Card>

      <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:1.5,
        textTransform:"uppercase",marginBottom:12}}>
        Monitored Assets ({assets.length})
      </div>
      {assets.length===0&&(
        <div style={{textAlign:"center",padding:40,color:C.muted,fontSize:13,
          background:C.surface,border:`1px solid ${C.border}`,borderRadius:12}}>
          No assets yet. Add a software or service above to start CVE monitoring.
        </div>
      )}
      {assets.map(asset=>(
        <div key={asset.id} style={{background:C.surface,border:`1px solid ${C.border}`,
          borderRadius:12,padding:18,marginBottom:12,boxShadow:C.shadow}}>
          <div style={{display:"flex",justifyContent:"space-between",
            alignItems:"flex-start",flexWrap:"wrap",gap:8}}>
            <div style={{flex:1}}>
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6,flexWrap:"wrap"}}>
                <span style={{fontSize:15,fontWeight:700,color:C.white||C.textHi}}>{asset.name}</span>
                {asset.vendor&&<span style={{fontSize:12,color:C.muted}}>{asset.vendor}</span>}
                {asset.version&&(
                  <span style={{fontSize:11,padding:"1px 7px",borderRadius:3,
                    background:C.badge||C.surfaceHi,color:C.muted,fontFamily:"monospace"}}>
                    v{asset.version}
                  </span>
                )}
                <span style={{fontSize:11,padding:"1px 7px",borderRadius:3,
                  background:C.surfaceHi,color:C.accentText}}>
                  {ASSET_TYPES.find(t=>t.val===asset.asset_type)?.label||asset.asset_type||"application"}
                </span>
              </div>
              <div style={{display:"flex",gap:14,fontSize:12,flexWrap:"wrap",marginBottom:4}}>
                <span style={{color:C.text}}>{asset.cve_count||0} CVEs found</span>
                <span style={{color:C.muted}}>
                  {asset.version?`Monitoring v${asset.version}`:"Monitoring all versions"}
                </span>
                {(asset.kev_unpatched||0)>0&&(
                  <span style={{color:C.red,fontWeight:700}}>🚨 {asset.kev_unpatched} KEV unpatched</span>
                )}
                {(asset.critical_unpatched||0)>0&&(
                  <span style={{color:C.amber,fontWeight:600}}>⚠ {asset.critical_unpatched} critical</span>
                )}
              </div>
              {asset.cpe&&(
                <div style={{fontSize:10,color:C.muted,fontFamily:"monospace",
                  marginTop:2,opacity:.6,wordBreak:"break-all"}}>{asset.cpe}</div>
              )}
            </div>
            <Btn onClick={()=>{api(`/assets/${asset.id}`,{method:"DELETE"},token)
              .then(()=>{load();if(onChanged)onChanged();});}}
              variant="danger" C={C} sm>Remove</Btn>
          </div>
        </div>
      ))}
    </div>
  );
}


// ── CVE DASHBOARD ─────────────────────────────────────────────────────────────
function CVEDashboard({token,C}){
  const THIS_YEAR = new Date().getFullYear();
  const YEARS = [THIS_YEAR, THIS_YEAR-1, THIS_YEAR-2, 0]; // 0 = all time

  const [allCves,setAllCves]=useState([]);
  const [assets,setAssets]=useState([]);
  const [summary,setSummary]=useState(null);
  const [selectedCVE,setSelectedCVE]=useState(null);
  const [selectedAsset,setSelectedAsset]=useState(null);
  const [loading,setLoading]=useState(false);
  const [polling,setPolling]=useState(false);
  const [pollResult,setPollResult]=useState(null);
  const [subView,setSubView]=useState("cves");
  const [filterPatch,setFilterPatch]=useState("all");
  const [filterKEV,setFilterKEV]=useState(false);
  const [yearFilter,setYearFilter]=useState(0); // 0 = all time

  const fetchData=useCallback(async()=>{
    setLoading(true);
    const [cvesRes,summaryRes,assetsRes]=await Promise.all([
      api("/cves",{},token),
      api("/cves/stats/summary",{},token),
      api("/assets",{},token),
    ]);
    if(cvesRes.ok)  setAllCves(await cvesRes.json());
    if(summaryRes.ok) setSummary(await summaryRes.json());
    if(assetsRes.ok)  setAssets(await assetsRes.json());
    setLoading(false);
  },[token]);

  useEffect(()=>{fetchData();},[fetchData]);

  async function pollNow(){
    setPolling(true);setPollResult(null);
    const r=await api("/cves/poll-now",{method:"POST"},token);
    if(r.ok){const d=await r.json();setPollResult(d);await fetchData();}
    setPolling(false);
  }

  // Filter CVEs by year, patch status, KEV
  const filterCve = (c, assetId=null) => {
    if(assetId && c.asset_id !== assetId) return false;
    if(yearFilter !== 0){
      const year = (c.published_date||"").slice(0,4);
      if(year && parseInt(year) !== yearFilter) return false;
    }
    if(filterPatch==="patched"   &&  !c.patch_available) return false;
    if(filterPatch==="unpatched" && c.patch_available)   return false;
    if(filterKEV && !c.kev_listed) return false;
    return true;
  };

  const assetCves = allCves.filter(c => filterCve(c, selectedAsset?.id));

  // Build per-asset summaries using the same year filter
  const assetSummaries = assets.map(a=>{
    const thisCves = allCves.filter(c => {
      if(c.asset_id !== a.id) return false;
      if(yearFilter !== 0){
        const year = (c.published_date||"").slice(0,4);
        if(year && parseInt(year) !== yearFilter) return false;
      }
      return true;
    });
    return {
      ...a,
      cveCount:  thisCves.length,
      critical:  thisCves.filter(c=>(c.cvss_score||0)>=9).length,
      high:      thisCves.filter(c=>(c.cvss_score||0)>=7&&(c.cvss_score||0)<9).length,
      kev:       thisCves.filter(c=>c.kev_listed).length,
      unpatched: thisCves.filter(c=>!c.patch_available).length,
      patched:   thisCves.filter(c=>c.patch_available).length,
    };
  });

  const yearLabel = yearFilter === 0 ? "All time" : String(yearFilter);

  return(
    <div>
      {selectedCVE&&<CVEDetail cve={selectedCVE} token={token} onClose={()=>setSelectedCVE(null)} C={C}/>}

      {/* Tab bar */}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20,flexWrap:"wrap",gap:10}}>
        <div style={{display:"flex",gap:4,background:C.surfaceHi,borderRadius:10,padding:3}}>
          {[["cves","CVE Monitor"],["assets","Asset Registry"]].map(([id,label])=>(
            <button key={id} onClick={()=>{setSubView(id);setSelectedAsset(null);}}
              style={{padding:"8px 18px",borderRadius:8,border:"none",cursor:"pointer",
                fontSize:13,fontFamily:"inherit",fontWeight:600,
                background:subView===id?C.accent:"transparent",
                color:subView===id?"#fff":C.muted}}>
              {label}
            </button>
          ))}
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
          {/* Year selector */}
          <div style={{display:"flex",gap:3,background:C.surfaceHi,borderRadius:8,padding:3}}>
            {YEARS.map(y=>(
              <button key={y} onClick={()=>{setYearFilter(y);setSelectedAsset(null);}}
                style={{padding:"5px 12px",borderRadius:6,border:"none",cursor:"pointer",
                  fontSize:12,fontFamily:"inherit",fontWeight:600,
                  background:yearFilter===y?C.accent:"transparent",
                  color:yearFilter===y?"#fff":C.muted}}>
                {y===0?"All":String(y)}
              </button>
            ))}
          </div>
          {summary?.last_poll&&(
            <span style={{fontSize:11,color:C.muted}}>
              Last poll: {new Date(summary.last_poll).toLocaleString()}
            </span>
          )}
          <button onClick={fetchData}
            style={{width:32,height:32,display:"flex",alignItems:"center",justifyContent:"center",
              background:"none",border:`1px solid ${C.border}`,color:C.muted,
              borderRadius:8,cursor:"pointer",fontSize:14}}>↻</button>
          <button onClick={pollNow} disabled={polling}
            style={{padding:"7px 16px",background:polling?C.accentDim:C.accent,border:"none",
              color:"#fff",borderRadius:8,cursor:"pointer",fontSize:12,
              fontFamily:"inherit",fontWeight:600,opacity:polling?0.6:1}}>
            {polling?"Polling NVD...":"⟳ Poll Now"}
          </button>
        </div>
      </div>

      {/* Poll result banner */}
      {pollResult&&(
        <div style={{marginBottom:16,padding:"12px 16px",background:C.green+"10",
          border:`1px solid ${C.green}30`,borderRadius:10,fontSize:13,color:C.text,
          display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <span>
            <strong style={{color:C.green}}>Poll complete</strong>{" — "}
            {pollResult.new_cves} new CVEs · {pollResult.new_iocs} IOCs auto-added ·{" "}
            {pollResult.patches_detected} patches detected · {pollResult.assets_polled} assets scanned
          </span>
          <button onClick={()=>setPollResult(null)}
            style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:18,padding:0}}>×</button>
        </div>
      )}

      {/* Asset Registry tab */}
      {subView==="assets"&&(
        <AssetManager token={token} C={C} onChanged={fetchData}/>
      )}

      {/* CVE Monitor tab */}
      {subView==="cves"&&(
        <>
          {/* ── Asset list view (default) ─────────────────────────────────── */}
          {!selectedAsset&&(
            <>
              {/* Summary strip */}
              {summary&&(
                <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(130px,1fr))",gap:12,marginBottom:24}}>
                  {[["Total CVEs",summary.total,C.accentText],
                    ["Unpatched",summary.unpatched,C.red],
                    ["Patched",summary.patched,C.green],
                    ["CISA KEV",summary.kev_unpatched,C.red],
                    ["Critical",summary.critical_unpatched,C.amber],
                  ].map(([label,val,color])=>(
                    <StatCard key={label} label={label} value={val||0} color={color} C={C}/>
                  ))}
                </div>
              )}

              {/* Year note */}
              <div style={{fontSize:12,color:C.muted,marginBottom:14}}>
                Showing CVEs published — <strong style={{color:C.accentText}}>{yearLabel}</strong>.
                Click a software to view its CVEs.
              </div>

              {/* Asset cards */}
              {loading&&<div style={{textAlign:"center",padding:48,color:C.muted}}>Loading...</div>}
              {!loading&&assetSummaries.length===0&&(
                <div style={{textAlign:"center",padding:60,background:C.surface,
                  border:`1px solid ${C.border}`,borderRadius:12,color:C.muted}}>
                  <div style={{fontSize:32,marginBottom:12}}>🛡️</div>
                  <div style={{fontSize:14,fontWeight:700,color:C.white||C.textHi,marginBottom:8}}>
                    No software being monitored
                  </div>
                  <div style={{fontSize:13,marginBottom:16}}>
                    Add software to the Asset Registry to start monitoring for CVEs.
                  </div>
                  <Btn onClick={()=>setSubView("assets")} C={C}>Go to Asset Registry</Btn>
                </div>
              )}
              {assetSummaries.map(asset=>{
                const hasKev  = asset.kev > 0;
                const hasCrit = asset.critical > 0;
                const color   = hasKev?C.red:hasCrit?C.amber:asset.cveCount>0?C.text:C.muted;
                return(
                  <div key={asset.id} onClick={()=>setSelectedAsset(asset)}
                    style={{background:C.surface,border:`1px solid ${hasKev?C.red+"40":C.border}`,
                      borderRadius:12,padding:"18px 20px",marginBottom:12,
                      cursor:"pointer",boxShadow:C.shadow,transition:"all .15s"}}
                    onMouseEnter={e=>{e.currentTarget.style.borderColor=C.accent;e.currentTarget.style.boxShadow=C.shadowMd||C.shadow;}}
                    onMouseLeave={e=>{e.currentTarget.style.borderColor=hasKev?C.red+"40":C.border;e.currentTarget.style.boxShadow=C.shadow;}}>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",flexWrap:"wrap",gap:12}}>
                      <div>
                        <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:6,flexWrap:"wrap"}}>
                          <span style={{fontSize:16,fontWeight:700,color:C.white||C.textHi}}>{asset.name}</span>
                          {asset.vendor&&<span style={{fontSize:13,color:C.muted}}>{asset.vendor}</span>}
                          {asset.version&&(
                            <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,
                              background:C.surfaceHi,color:C.muted,fontFamily:"monospace"}}>
                              v{asset.version}
                            </span>
                          )}
                          {hasKev&&(
                            <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,
                              background:C.red+"20",color:C.red,border:`1px solid ${C.red}40`}}>
                              🚨 CISA KEV
                            </span>
                          )}
                        </div>
                        {/* CVE breakdown pills */}
                        <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                          {asset.cveCount===0?(
                            <span style={{fontSize:12,color:C.muted}}>No CVEs found ({yearLabel})</span>
                          ):(
                            <>
                              {asset.critical>0&&<span style={{fontSize:12,padding:"2px 10px",borderRadius:20,background:C.red+"15",color:C.red,fontWeight:600}}>{asset.critical} Critical</span>}
                              {asset.high>0&&    <span style={{fontSize:12,padding:"2px 10px",borderRadius:20,background:C.amber+"15",color:C.amber,fontWeight:600}}>{asset.high} High</span>}
                              {asset.unpatched>0&&<span style={{fontSize:12,padding:"2px 10px",borderRadius:20,background:C.red+"10",color:C.red,fontWeight:500}}>{asset.unpatched} Unpatched</span>}
                              {asset.patched>0&&  <span style={{fontSize:12,padding:"2px 10px",borderRadius:20,background:C.green+"10",color:C.green,fontWeight:500}}>{asset.patched} Patched</span>}
                            </>
                          )}
                        </div>
                      </div>
                      <div style={{display:"flex",alignItems:"center",gap:16}}>
                        <div style={{textAlign:"right"}}>
                          <div style={{fontSize:32,fontWeight:700,color}}>{asset.cveCount}</div>
                          <div style={{fontSize:11,color:C.muted}}>CVEs ({yearLabel})</div>
                        </div>
                        <NavIcon name="chevronRight" size={20} color={C.muted}/>
                      </div>
                    </div>
                  </div>
                );
              })}
            </>
          )}

          {/* ── Asset drill-down view ─────────────────────────────────────── */}
          {selectedAsset&&(
            <>
              {/* Breadcrumb */}
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:20}}>
                <button onClick={()=>setSelectedAsset(null)}
                  style={{background:"none",border:"none",color:C.accentText,cursor:"pointer",
                    fontSize:13,fontFamily:"inherit",fontWeight:600,padding:0,
                    display:"flex",alignItems:"center",gap:4}}>
                  ← CVE Monitor
                </button>
                <span style={{color:C.muted}}>/</span>
                <span style={{fontSize:13,color:C.text,fontWeight:600}}>{selectedAsset.name}</span>
                {selectedAsset.vendor&&<span style={{fontSize:12,color:C.muted}}>{selectedAsset.vendor}</span>}
              </div>

              {/* Asset header */}
              <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
                padding:"16px 20px",marginBottom:16,boxShadow:C.shadow,
                display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:12}}>
                <div>
                  <div style={{fontSize:18,fontWeight:700,color:C.white||C.textHi,marginBottom:4}}>
                    {selectedAsset.name}
                    {selectedAsset.version&&<span style={{fontSize:13,color:C.muted,fontWeight:400,marginLeft:10}}>v{selectedAsset.version}</span>}
                  </div>
                  <div style={{fontSize:12,color:C.muted}}>
                    {selectedAsset.vendor} · CVEs — {yearLabel}
                  </div>
                </div>
                <div style={{display:"flex",gap:8,alignItems:"center"}}>
                  {/* Patch filter */}
                  <div style={{display:"flex",gap:3,background:C.surfaceHi,borderRadius:8,padding:3}}>
                    {[["all","All"],["unpatched","Unpatched"],["patched","Patched"]].map(([val,label])=>(
                      <button key={val} onClick={()=>setFilterPatch(val)}
                        style={{padding:"5px 12px",borderRadius:6,border:"none",cursor:"pointer",
                          fontSize:11,fontFamily:"inherit",fontWeight:600,
                          background:filterPatch===val?C.accent:"transparent",
                          color:filterPatch===val?"#fff":C.muted}}>
                        {label}
                      </button>
                    ))}
                  </div>
                  <label style={{display:"flex",alignItems:"center",gap:5,fontSize:12,color:C.muted,cursor:"pointer",whiteSpace:"nowrap"}}>
                    <input type="checkbox" checked={filterKEV} onChange={e=>setFilterKEV(e.target.checked)} style={{accentColor:C.accent}}/>
                    KEV Only
                  </label>
                </div>
              </div>

              {/* CVE count for this asset */}
              <div style={{fontSize:13,color:C.muted,marginBottom:12}}>
                <strong style={{color:C.white||C.textHi}}>{assetCves.length}</strong> CVE{assetCves.length!==1?"s":""} found ({yearLabel})
                {assetCves.length===0&&allCves.filter(c=>c.asset_id===selectedAsset.id).length>0&&(
                  <span style={{color:C.amber}}> — older CVEs exist but are filtered out</span>
                )}
              </div>

              {/* CVE table */}
              {assetCves.length===0?(
                <div style={{textAlign:"center",padding:48,background:C.surface,
                  border:`1px solid ${C.border}`,borderRadius:12,color:C.muted}}>
                  <div style={{fontSize:32,marginBottom:12}}>✅</div>
                  <div style={{fontSize:14,fontWeight:700,color:C.white||C.textHi,marginBottom:8}}>
                    No CVEs found ({yearLabel})
                  </div>
                  <div style={{fontSize:13}}>
                    {filterPatch!=="all"||filterKEV?"Try removing filters.":"Run Poll Now to fetch the latest CVEs from NVD."}
                  </div>
                </div>
              ):(
                <div style={{background:C.surface,border:`1px solid ${C.border}`,
                  borderRadius:12,overflow:"hidden",boxShadow:C.shadow}}>
                  <div style={{overflowX:"auto"}}>
                    <table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}>
                      <thead>
                        <tr style={{background:C.surfaceHi}}>
                          {[["CVE ID","180px"],["Severity","110px"],["EPSS","80px"],
                            ["Vulnerability","auto"],["Published","110px"],["Patch","130px"]].map(([h,w])=>(
                            <th key={h} style={{padding:"11px 16px",textAlign:"left",
                              color:C.muted,fontSize:11,fontWeight:600,whiteSpace:"nowrap",
                              letterSpacing:"0.04em",borderBottom:`1px solid ${C.border}`,
                              width:w,minWidth:w==="auto"?150:w}}>
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {assetCves.map(cve=>(
                          <tr key={cve.id||cve.cve_id} onClick={()=>setSelectedCVE(cve)}
                            style={{borderBottom:`1px solid ${C.border}`,cursor:"pointer",
                              background:cve.kev_listed?C.red+"05":"transparent"}}
                            onMouseEnter={e=>e.currentTarget.style.background=C.surfaceHi}
                            onMouseLeave={e=>e.currentTarget.style.background=cve.kev_listed?C.red+"05":"transparent"}>

                            <td style={{padding:"13px 16px"}}>
                              <div style={{display:"flex",alignItems:"center",gap:6}}>
                                <span style={{fontWeight:700,fontSize:13,color:C.white||C.textHi,letterSpacing:"-0.01em"}}>
                                  {cve.cve_id}
                                </span>
                                <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                                  target="_blank" rel="noreferrer" onClick={e=>e.stopPropagation()}
                                  style={{opacity:.5,display:"flex",alignItems:"center"}}>
                                  <NavIcon name="externalLink" size={12} color={C.muted}/>
                                </a>
                              </div>
                              {cve.kev_listed&&(
                                <div style={{fontSize:10,color:C.red,fontWeight:600,marginTop:3,
                                  display:"flex",alignItems:"center",gap:3}}>
                                  <span style={{width:5,height:5,borderRadius:"50%",background:C.red,display:"inline-block"}}/>
                                  CISA KEV
                                </div>
                              )}
                            </td>

                            <td style={{padding:"13px 16px"}}>
                              <SevBadge severity={cve.cvss_severity} score={cve.cvss_score} C={C}/>
                            </td>

                            <td style={{padding:"13px 16px"}}>
                              {cve.epss_score!=null?(
                                <span style={{fontSize:12,fontWeight:600,
                                  color:cve.epss_score>=0.5?C.red:cve.epss_score>=0.1?C.amber:C.muted}}>
                                  {(cve.epss_score*100).toFixed(1)}%
                                </span>
                              ):<span style={{color:C.muted}}>—</span>}
                            </td>

                            <td style={{padding:"13px 16px",maxWidth:320}}>
                              <div style={{fontSize:13,color:C.text,overflow:"hidden",
                                textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:320}}
                                title={cve.description||""}>
                                {(cve.title||cve.description||"").replace(/^CVE-\d+-\d+:\s*/,"")}
                              </div>
                            </td>

                            <td style={{padding:"13px 16px",fontSize:12,color:C.muted,whiteSpace:"nowrap"}}>
                              {cve.published_date||"—"}
                            </td>

                            <td style={{padding:"13px 16px"}}>
                              <PatchBadge available={cve.patch_available} url={cve.patch_url} C={C}/>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div style={{padding:"10px 20px",borderTop:`1px solid ${C.border}`,
                    fontSize:11,color:C.muted,display:"flex",justifyContent:"space-between"}}>
                    <span>Click any row for full details, IOCs, references, and patch link</span>
                    <span>{assetCves.length} CVEs · {yearLabel} · sorted by severity</span>
                  </div>
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

// ── GEO MAP ───────────────────────────────────────────────────────────────────
function GeoMap({token,C}){
  const [geo,setGeo]=useState(null);
  useEffect(()=>{api("/stats/geo",{},token).then(r=>r.ok?r.json():null).then(d=>{if(d)setGeo(d);});},[token]);
  if(!geo)return <div style={{padding:40,textAlign:"center",color:C.muted}}>Loading geographic data...</div>;
  if(geo.countries.length===0)return <div style={{padding:40,textAlign:"center",color:C.muted}}>No geographic data yet. Add IP-type IOCs to see country breakdown.</div>;
  const max=geo.countries[0]?.count||1;
  return(
    <div>
      <div style={{marginBottom:20,padding:14,background:C.accentDim,border:`1px solid ${C.accent}28`,borderRadius:10,fontSize:13,color:C.accentText}}>Geographic origin of IP IOCs based on AbuseIPDB and VirusTotal enrichment data.</div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(270px,1fr))",gap:12}}>
        {geo.countries.map(c=>{
          const flag=COUNTRY_FLAGS[c.code]||"🌐";const name=COUNTRY_NAMES[c.code]||c.code;const pct=Math.round((c.count/max)*100);
          return(<div key={c.code} style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:10,padding:14,boxShadow:C.shadow}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
              <div style={{display:"flex",alignItems:"center",gap:10}}><span style={{fontSize:20}}>{flag}</span><div><div style={{fontSize:13,fontWeight:600,color:C.white}}>{name}</div><div style={{fontSize:11,color:C.muted}}>{c.code}</div></div></div>
              <div style={{textAlign:"right"}}><div style={{fontSize:20,fontWeight:700,color:pct>=80?C.red:pct>=40?C.amber:C.green}}>{c.count}</div><div style={{fontSize:11,color:C.muted}}>IOCs</div></div>
            </div>
            <div style={{height:4,background:C.border,borderRadius:2,overflow:"hidden"}}><div style={{width:`${pct}%`,height:"100%",background:pct>=80?C.red:pct>=40?C.amber:C.green,borderRadius:2}}/></div>
          </div>);
        })}
      </div>
    </div>
  );
}

// ── INTEL WALL ────────────────────────────────────────────────────────────────
// ── CVE WALL ──────────────────────────────────────────────────────────────────
function CVELookup({token,C,initialId=""}){
  const [cveId,setCveId]=useState(initialId);
  const [result,setResult]=useState(null);
  const [loading,setLoading]=useState(false);
  const [err,setErr]=useState("");
  const [showReport,setShowReport]=useState(false);
  const CVE_RE=/^CVE-\d{4}-\d{4,}$/i;

  useEffect(()=>{ if(initialId&&CVE_RE.test(initialId)) doLookup(initialId); },[initialId]);// eslint-disable-line react-hooks/exhaustive-deps

  async function doLookup(id){
    const q=(id||cveId).trim().toUpperCase();
    if(!CVE_RE.test(q)){setErr("Enter a valid CVE ID e.g. CVE-2024-12345");return;}
    setLoading(true);setErr("");setResult(null);
    try{
      const r=await api(`/cve/lookup?id=${q}`,{},token);
      if(r.ok) setResult(await r.json());
      else {const e=await r.json();setErr(e.detail||"Lookup failed");}
    }catch{setErr("Cannot reach server.");}
    setLoading(false);
  }

  const SEV_COLORS={CRITICAL:C.red,HIGH:C.amber,MEDIUM:C.purple,LOW:C.green};
  const STATUS_ICON={"ok":"✓","not_found":"—","error":"✗"};

  return(
    <div style={{maxWidth:1000}}>
      {/* Search bar */}
      <div style={{display:"flex",gap:10,marginBottom:24}}>
        <input value={cveId} onChange={e=>setCveId(e.target.value)}
          onKeyDown={e=>{if(e.key==="Enter")doLookup();}}
          placeholder="Enter CVE ID — e.g. CVE-2024-12345"
          style={{flex:1,background:C.inputBg,border:`1px solid ${C.inputBorder}`,
            color:C.inputText,padding:"12px 16px",borderRadius:10,fontSize:15,
            outline:"none",fontFamily:"monospace",letterSpacing:"0.02em"}}/>
        <Btn onClick={()=>doLookup()} disabled={loading||!cveId.trim()} C={C}>
          {loading?"Looking up...":"Lookup CVE"}
        </Btn>
      </div>

      {err&&<div style={{padding:"10px 14px",background:C.red+"10",border:`1px solid ${C.red}30`,borderRadius:8,color:C.red,fontSize:13,marginBottom:16}}>{err}</div>}
      {loading&&(
        <div style={{textAlign:"center",padding:48,color:C.muted}}>
          <div style={{fontSize:14,marginBottom:8}}>Querying NVD, CVE.org, OSV, CVE Trends, EPSS...</div>
          <div style={{fontSize:12}}>Fetching from all sources in parallel</div>
        </div>
      )}

      {result&&(
        <div>
          {/* Header */}
          <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
            padding:"20px 24px",marginBottom:16,boxShadow:C.shadow}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",
              flexWrap:"wrap",gap:12,marginBottom:12}}>
              <div>
                <div style={{fontSize:22,fontWeight:700,color:C.white||C.textHi,
                  fontFamily:"monospace",marginBottom:6}}>{result.cve_id}</div>
                <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                  {result.in_kev&&(
                    <span style={{fontSize:12,padding:"3px 10px",borderRadius:4,fontWeight:700,
                      background:C.red+"20",color:C.red,border:`1px solid ${C.red}30`}}>
                      🚨 CISA KEV — Added {result.kev_date}
                    </span>
                  )}
                  {result.epss&&(
                    <span style={{fontSize:12,padding:"3px 10px",borderRadius:4,fontWeight:600,
                      background:result.epss.epss>=0.5?C.red+"15":result.epss.epss>=0.1?C.amber+"15":C.accentDim,
                      color:result.epss.epss>=0.5?C.red:result.epss.epss>=0.1?C.amber:C.accentText}}>
                      EPSS {(result.epss.epss*100).toFixed(1)}% · {(result.epss.percentile*100).toFixed(0)}th percentile
                    </span>
                  )}
                  {/* CVSS from NVD */}
                  {result.sources?.find(s=>s.source==="NVD"&&s.cvss)?.cvss&&(()=>{
                    const cvss=result.sources.find(s=>s.source==="NVD").cvss;
                    return(
                      <span style={{fontSize:12,padding:"3px 10px",borderRadius:4,fontWeight:700,
                        background:(SEV_COLORS[cvss.severity]||C.muted)+"20",
                        color:SEV_COLORS[cvss.severity]||C.muted,
                        border:`1px solid ${(SEV_COLORS[cvss.severity]||C.muted)}30`}}>
                        {cvss.severity} {cvss.score}
                      </span>
                    );
                  })()}
                </div>
              </div>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                {[
                  {name:"NVD",    url:`https://nvd.nist.gov/vuln/detail/${result.cve_id}`},
                  {name:"CVE.org",url:`https://www.cve.org/CVERecord?id=${result.cve_id}`},
                  {name:"OSV",    url:`https://osv.dev/vulnerability/${result.cve_id}`},
                ].map(link=>(
                  <a key={link.name} href={link.url} target="_blank" rel="noreferrer"
                    style={{fontSize:11,padding:"5px 12px",borderRadius:6,background:C.accentDim,
                      color:C.accentText,fontWeight:600,border:`1px solid ${C.accent}30`,
                      display:"flex",alignItems:"center",gap:4,textDecoration:"none"}}>
                    {link.name} <NavIcon name="externalLink" size={10} color={C.accentText}/>
                  </a>
                ))}
              <button onClick={()=>setShowReport(true)}
                  style={{padding:"8px 16px",background:C.accent,border:"none",color:"#fff",
                    borderRadius:8,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:700,
                    alignSelf:"flex-start"}}>
                  ⚡ Generate Report
                </button>
              </div>
            </div>
            {showReport&&<CVEReportModal cveId={result.cve_id} token={token} C={C} onClose={()=>setShowReport(false)}/>}
            {/* Description from NVD */}
            {result.sources?.find(s=>s.source==="NVD"&&s.description)?.description&&(
              <div style={{fontSize:13,color:C.text,lineHeight:1.7,padding:"12px 14px",
                background:C.surfaceHi,borderRadius:8}}>
                {result.sources.find(s=>s.source==="NVD").description}
              </div>
            )}
          </div>

          {/* Source cards */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(280px,1fr))",
            gap:14,marginBottom:16}}>
            {result.sources.map(src=>(
              <div key={src.source} style={{background:C.surface,
                border:`1px solid ${src.status==="ok"?C.border:C.border+"60"}`,
                borderRadius:12,padding:"16px 18px",boxShadow:C.shadow,
                opacity:src.status==="ok"?1:0.7}}>
                <div style={{display:"flex",justifyContent:"space-between",
                  alignItems:"center",marginBottom:10}}>
                  <span style={{fontSize:14,fontWeight:700,color:C.white||C.textHi}}>
                    {src.source}
                  </span>
                  <span style={{fontSize:11,fontWeight:600,
                    color:src.status==="ok"?C.green:src.status==="not_found"?C.muted:C.red}}>
                    {STATUS_ICON[src.status]} {src.status==="ok"?"Found":src.status==="not_found"?"Not in database":"Error"}
                  </span>
                </div>

                {src.status==="ok"&&src.source==="NVD"&&(
                  <div>
                    {src.cvss&&<div style={{fontSize:12,color:SEV_COLORS[src.cvss.severity]||C.muted,
                      fontWeight:600,marginBottom:6}}>
                      CVSS {src.cvss.version}: {src.cvss.score} {src.cvss.severity}
                    </div>}
                    {src.weaknesses?.length>0&&<div style={{fontSize:11,color:C.muted,marginBottom:4}}>
                      CWE: {src.weaknesses.join(", ")}
                    </div>}
                    {src.published&&<div style={{fontSize:11,color:C.muted}}>Published: {src.published}</div>}
                    {src.affected_cpes?.length>0&&(
                      <div style={{marginTop:8}}>
                        <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:4,textTransform:"uppercase"}}>
                          Affected CPEs
                        </div>
                        <div style={{maxHeight:80,overflowY:"auto"}}>
                          {src.affected_cpes.slice(0,4).map((cpe,i)=>(
                            <div key={i} style={{fontSize:10,color:C.muted,fontFamily:"monospace",
                              marginBottom:2,wordBreak:"break-all"}}>{cpe}</div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {src.status==="ok"&&src.source==="CVE.org"&&(
                  <div>
                    {src.state&&<div style={{fontSize:11,color:C.muted,marginBottom:6}}>
                      State: <span style={{fontWeight:600,color:C.accentText}}>{src.state}</span>
                    </div>}
                    {src.affected?.length>0&&(
                      <div>
                        <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:4,textTransform:"uppercase"}}>Affected</div>
                        {src.affected.slice(0,4).map((a,i)=>(
                          <div key={i} style={{fontSize:11,color:C.text,marginBottom:2}}>{a}</div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {src.status==="ok"&&src.source==="OSV"&&(
                  <div>
                    <div style={{fontSize:12,color:C.muted,marginBottom:8}}>
                      {src.count} related {src.count===1?"advisory":"advisories"}
                    </div>
                    {src.vulns?.slice(0,2).map((v,i)=>(
                      <div key={i} style={{marginBottom:8,padding:"8px 10px",
                        background:C.surfaceHi,borderRadius:6}}>
                        <div style={{fontSize:11,fontWeight:700,color:C.accentText,marginBottom:4}}>
                          {v.id}
                        </div>
                        {v.packages?.slice(0,3).map((p,j)=>(
                          <div key={j} style={{fontSize:10,color:C.muted}}>
                            {p.ecosystem}: <span style={{color:C.text}}>{p.name}</span>
                            {p.fix&&<span style={{color:C.green}}> → fix: {p.fix}</span>}
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                )}

                {src.status==="ok"&&src.source==="CVE Trends"&&(
                  <div>
                    <div style={{fontSize:13,fontWeight:600,color:src.trending?C.accentText:C.muted,marginBottom:6}}>
                      {src.trending?"📈 Currently trending":"Not trending"}
                    </div>
                    {src.count_24h>0&&(
                      <div style={{fontSize:12,color:C.muted}}>{src.count_24h} mentions in last 24h</div>
                    )}
                  </div>
                )}

                {src.status==="error"&&(
                  <div style={{fontSize:11,color:C.red}}>{src.error||"Failed to fetch"}</div>
                )}
                {src.status==="not_found"&&(
                  <div style={{fontSize:11,color:C.muted}}>This CVE is not in the {src.source} database</div>
                )}
              </div>
            ))}
          </div>

          {/* All References unified */}
          {result.all_refs?.length>0&&(
            <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
              padding:"18px 20px",boxShadow:C.shadow}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:14,
                textTransform:"uppercase",letterSpacing:"0.06em"}}>
                All References ({result.all_refs.length})
              </div>
              <div style={{display:"grid",gap:8}}>
                {result.all_refs.map((ref,i)=>(
                  <div key={i} style={{display:"flex",alignItems:"flex-start",gap:10,
                    padding:"8px 10px",background:C.surfaceHi,borderRadius:6}}>
                    <div style={{flex:1,minWidth:0}}>
                      <a href={ref.url} target="_blank" rel="noreferrer"
                        style={{fontSize:12,color:C.accentText,wordBreak:"break-all",
                          textDecoration:"none",display:"flex",alignItems:"center",gap:4}}>
                        <NavIcon name="externalLink" size={11} color={C.accentText}/>
                        {ref.url}
                      </a>
                    </div>
                    <div style={{display:"flex",gap:4,flexShrink:0,flexWrap:"wrap",justifyContent:"flex-end"}}>
                      {ref.source&&(
                        <span style={{fontSize:9,padding:"1px 5px",borderRadius:3,
                          background:C.accentDim,color:C.accentText,fontWeight:700}}>
                          {ref.source}
                        </span>
                      )}
                      {ref.tags?.slice(0,2).map(t=>(
                        <span key={t} style={{fontSize:9,padding:"1px 5px",borderRadius:3,
                          background:C.surfaceHi,color:C.muted,border:`1px solid ${C.border}`}}>
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}


function CVEWall({token,C}){
  const [items,setItems]=useState([]); const [loading,setLoading]=useState(false);
  const [err,setErr]=useState("");
  const [activeSource,setActiveSource]=useState("all");
  const [activeSev,setActiveSev]=useState("all");
  const [activeCat,setActiveCat]=useState("all");
  const [timeRange,setTimeRange]=useState("all");

  const CATEGORIES=["all","CVE","Advisory","KEV","0day","Analysis"];
  const SEVERITIES=["all","Critical","High","Medium","Low"];
  const TIME_OPTS=[["all","All time"],["today","Today"],["7d","7 days"],["30d","30 days"]];
  const SEV_COLORS={Critical:C.red,High:C.amber,Medium:C.purple,Low:C.green};

  async function fetchWall(){
    setLoading(true);setErr("");
    try{
      const r=await api("/cve-wall?category=all",{},token);
      if(r.ok){const d=await r.json();setItems(d.items||[]);}
      else setErr("Failed to fetch CVE wall.");
    }catch(e){setErr("Cannot reach server.");}
    setLoading(false);
  }
  useEffect(()=>{fetchWall();},[]);// eslint-disable-line react-hooks/exhaustive-deps

  const sources=["all",...[...new Set(items.map(i=>i.source).filter(Boolean))]];
  const filtered=items.filter(i=>{
    if(activeSource!=="all"&&i.source!==activeSource) return false;
    if(activeCat!=="all"&&i.category!==activeCat) return false;
    if(activeSev!=="all"&&i.severity!==activeSev) return false;
    if(timeRange!=="all"&&i.date){
      const now=new Date(); const d=new Date(i.date);
      if(timeRange==="today"){const s=new Date(now);s.setHours(0,0,0,0);if(d<s)return false;}
      else if(timeRange==="7d"&&d<new Date(now-7*864e5))return false;
      else if(timeRange==="30d"&&d<new Date(now-30*864e5))return false;
    }
    return true;
  });

  const Pill=({label,active,onClick})=>(
    <button onClick={onClick} style={{padding:"5px 11px",borderRadius:6,border:"none",
      cursor:"pointer",fontSize:11,fontFamily:"inherit",fontWeight:600,
      background:active?C.accent:"transparent",color:active?"#fff":C.muted}}>
      {label}
    </button>
  );

  return(
    <div>
      {/* Filter bar */}
      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
        padding:"14px 16px",marginBottom:16,boxShadow:C.shadow}}>
        <div style={{display:"flex",gap:16,flexWrap:"wrap",alignItems:"flex-end"}}>
          {[["Type",CATEGORIES,activeCat,setActiveCat,c=>c==="all"?"All":c],
            ["Severity",SEVERITIES,activeSev,setActiveSev,s=>s==="all"?"All":s],
            ["Time",TIME_OPTS.map(([v])=>v),timeRange,setTimeRange,v=>TIME_OPTS.find(([k])=>k===v)?.[1]||v]
          ].map(([label,opts,val,setVal,fmt])=>(
            <div key={label}>
              <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:5,
                textTransform:"uppercase",letterSpacing:"0.05em"}}>{label}</div>
              <div style={{display:"flex",gap:2,background:C.surfaceHi,borderRadius:8,padding:2}}>
                {opts.map(o=><Pill key={o} label={fmt(o)} active={val===o} onClick={()=>setVal(o)}/>)}
              </div>
            </div>
          ))}
          <div style={{marginLeft:"auto"}}>
            <Btn onClick={fetchWall} disabled={loading} C={C}>{loading?"Fetching...":"⟳ Refresh"}</Btn>
          </div>
        </div>
        {/* Source pills */}
        {items.length>0&&(
          <div style={{display:"flex",gap:5,marginTop:12,flexWrap:"wrap"}}>
            {sources.map(s=>(
              <button key={s} onClick={()=>setActiveSource(s)}
                style={{padding:"3px 12px",borderRadius:20,cursor:"pointer",fontFamily:"inherit",
                  border:`1px solid ${activeSource===s?C.accent:C.border}`,
                  background:activeSource===s?C.accentDim:"transparent",
                  color:activeSource===s?C.accentText:C.muted,fontSize:11,
                  fontWeight:activeSource===s?600:400}}>
                {s==="all"?`All (${items.length})`:s}
              </button>
            ))}
          </div>
        )}
      </div>

      {err&&<div style={{padding:14,background:C.red+"10",border:`1px solid ${C.red}30`,borderRadius:8,color:C.red,fontSize:13,marginBottom:16}}>{err}</div>}
      {loading&&<div style={{textAlign:"center",padding:48,color:C.muted}}>Fetching vulnerability advisories from CISA, NVD, vendor feeds...</div>}
      {!loading&&items.length===0&&!err&&(
        <div style={{textAlign:"center",padding:48,color:C.muted}}>
          <div style={{fontSize:32,marginBottom:12}}>🛡️</div>
          <div style={{fontSize:14,fontWeight:600,color:C.white||C.textHi,marginBottom:8}}>CVE Wall</div>
          <div style={{fontSize:13,marginBottom:20}}>Pull the latest vulnerability advisories from CISA, NVD, Red Hat, Apple, Ubuntu and more.</div>
          <Btn onClick={fetchWall} C={C}>Fetch CVE Wall</Btn>
        </div>
      )}
      {items.length>0&&(
        <>
          {filtered.length===0?<div style={{textAlign:"center",padding:32,color:C.muted,background:C.surface,border:`1px solid ${C.border}`,borderRadius:12}}>No advisories match current filters.</div>:(
          <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,overflow:"hidden",boxShadow:C.shadow}}>
            <div style={{overflowX:"auto"}}>
              <table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}>
                <thead>
                  <tr style={{background:C.surfaceHi}}>
                    {[["Source","110px"],["Type","80px"],["Severity","90px"],["Advisory / CVE","auto"],["CVEs","130px"],["Date","100px"],["","40px"]].map(([h,w])=>(
                      <th key={h} style={{padding:"10px 14px",textAlign:"left",color:C.muted,fontSize:11,fontWeight:600,letterSpacing:"0.04em",whiteSpace:"nowrap",borderBottom:`1px solid ${C.border}`,width:w}}>{h.toUpperCase()}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((item,i)=>(
                    <tr key={i} style={{borderBottom:`1px solid ${C.border}`,transition:"background .1s"}}
                      onMouseEnter={e=>e.currentTarget.style.background=C.surfaceHi}
                      onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                      <td style={{padding:"11px 14px"}}><span style={{fontSize:11,fontWeight:700,color:C.accentText}}>{item.source}</span></td>
                      <td style={{padding:"11px 14px"}}>
                        <span style={{fontSize:10,padding:"2px 7px",borderRadius:4,fontWeight:700,
                          background:item.category==="KEV"?C.red+"20":item.category==="0day"?C.purple+"20":C.accentDim,
                          color:item.category==="KEV"?C.red:item.category==="0day"?C.purple:C.accentText}}>
                          {item.category}
                        </span>
                      </td>
                      <td style={{padding:"11px 14px"}}><span style={{fontSize:12,fontWeight:700,color:SEV_COLORS[item.severity]||C.muted}}>{item.severity}</span></td>
                      <td style={{padding:"11px 14px",maxWidth:380}}>
                        <div style={{fontSize:13,fontWeight:600,color:C.white||C.textHi,marginBottom:2,lineHeight:1.4}}>{item.title}</div>
                        {item.description&&<div style={{fontSize:11,color:C.muted,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:360}} title={item.description}>{item.description}</div>}
                      </td>
                      <td style={{padding:"11px 14px",minWidth:130}}>
                        {item.cves_mentioned?.length>0?(
                          <div style={{display:"flex",flexWrap:"wrap",gap:3}}>
                            {item.cves_mentioned.slice(0,3).map(cve=>(
                              <a key={cve} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noreferrer"
                                style={{fontSize:10,padding:"2px 6px",borderRadius:3,background:C.red+"15",color:C.red,fontFamily:"monospace",fontWeight:700,textDecoration:"none"}}>
                                {cve}
                              </a>
                            ))}
                            {item.cves_mentioned.length>3&&<span style={{fontSize:10,color:C.muted}}>+{item.cves_mentioned.length-3}</span>}
                          </div>
                        ):<span style={{color:C.muted,fontSize:11}}>—</span>}
                      </td>
                      <td style={{padding:"11px 14px",fontSize:11,color:C.muted,whiteSpace:"nowrap"}}>{item.date}</td>
                      <td style={{padding:"11px 14px"}}>
                        {item.url&&<a href={item.url} target="_blank" rel="noreferrer" style={{color:C.accentText,display:"flex",alignItems:"center"}}><NavIcon name="externalLink" size={11} color={C.accentText}/></a>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div style={{padding:"8px 16px",borderTop:`1px solid ${C.border}`,fontSize:11,color:C.muted,display:"flex",justifyContent:"space-between"}}>
              <span>Showing {filtered.length} of {items.length} advisories</span>
              <span>CISA · NVD · Red Hat · Apple · Ubuntu · Zero Day Initiative · PacketStorm · Kaspersky</span>
            </div>
          </div>
          )}
        </>
      )}
    </div>
  );
}

function IntelNews({token,C}){
  const [news,setNews]=useState([]); const [loading,setLoading]=useState(false);
  const [err,setErr]=useState(""); const [category,setCategory]=useState("all");
  const [activeSource,setActiveSource]=useState("all");

  async function fetchNews(){
    setLoading(true);setErr("");setNews([]);
    const r=await api("/ai/intel-news",{method:"POST",body:JSON.stringify({category})},token);
    if(r.ok){const d=await r.json();setNews(d.items||[]);}
    else setErr("Failed to fetch news.");
    setLoading(false);
  }

  const SEV_COLORS={Critical:C.red,High:C.amber,Medium:C.purple,Low:C.green};
  const CAT_COLORS={CVE:C.red,APT:C.purple,Ransomware:C.amber,Malware:C.amber,"Data Breach":C.red,Other:C.muted};

  // Get unique sources from results
  const sources=["all",...[...new Set(news.map(n=>n.source).filter(Boolean))]];
  const filtered=news.filter(n=>activeSource==="all"||n.source===activeSource);

  return(
    <div>
      <div style={{display:"flex",gap:10,marginBottom:20,flexWrap:"wrap",alignItems:"center"}}>
        <div style={{display:"flex",gap:4,background:C.surfaceHi,borderRadius:10,padding:3}}>
          {["all","cve","apt","ransomware","ioc"].map(t=>(
            <button key={t} onClick={()=>setCategory(t)}
              style={{padding:"7px 14px",borderRadius:7,border:"none",cursor:"pointer",
                fontSize:12,fontFamily:"inherit",fontWeight:600,
                background:category===t?C.accent:"transparent",
                color:category===t?"#fff":C.muted}}>
              {t.toUpperCase()}
            </button>
          ))}
        </div>
        <Btn onClick={fetchNews} disabled={loading} C={C}>{loading?"Fetching...":"⟳ Refresh Intel"}</Btn>
      </div>

      {!loading&&news.length===0&&!err&&(
        <div style={{textAlign:"center",padding:48,color:C.muted}}>
          <div style={{fontSize:32,marginBottom:12}}>📡</div>
          <div style={{fontSize:14,fontWeight:600,color:C.white||C.textHi,marginBottom:8}}>Cyber Intelligence Wall</div>
          <div style={{fontSize:13,marginBottom:20}}>Pull the latest threat intel from CISA, SANS ISC, BleepingComputer, and Krebs on Security.</div>
          <Btn onClick={fetchNews} C={C}>Fetch Latest Intel</Btn>
        </div>
      )}
      {err&&<div style={{padding:14,background:C.red+"10",border:`1px solid ${C.red}30`,borderRadius:8,color:C.red,fontSize:13,marginBottom:16}}>{err}</div>}
      {loading&&<div style={{textAlign:"center",padding:48,color:C.muted}}>Fetching from CISA, SANS ISC, BleepingComputer, Krebs...</div>}

      {news.length>0&&(
        <>
          {/* Source filter pills */}
          <div style={{display:"flex",gap:6,marginBottom:16,flexWrap:"wrap"}}>
            {sources.map(s=>(
              <button key={s} onClick={()=>setActiveSource(s)}
                style={{padding:"4px 14px",borderRadius:20,border:`1px solid ${activeSource===s?C.accent:C.border}`,
                  background:activeSource===s?C.accentDim:"transparent",
                  color:activeSource===s?C.accentText:C.muted,
                  cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:activeSource===s?600:400}}>
                {s==="all"?`All (${news.length})`:s}
              </button>
            ))}
          </div>

          {/* Table with Source column */}
          <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,overflow:"hidden",boxShadow:C.shadow}}>
            <div style={{overflowX:"auto"}}>
              <table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}>
                <thead>
                  <tr style={{background:C.surfaceHi}}>
                    {[["Source","130px"],["Category","100px"],["Severity","90px"],["Title","auto"],["Date","100px"],["","60px"]].map(([h,w])=>(
                      <th key={h} style={{padding:"10px 14px",textAlign:"left",color:C.muted,
                        fontSize:11,fontWeight:600,letterSpacing:"0.04em",whiteSpace:"nowrap",
                        borderBottom:`1px solid ${C.border}`,width:w}}>
                        {h.toUpperCase()}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((item,i)=>(
                    <tr key={i}
                      style={{borderBottom:`1px solid ${C.border}`,transition:"background .1s"}}
                      onMouseEnter={e=>e.currentTarget.style.background=C.surfaceHi}
                      onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                      {/* Source */}
                      <td style={{padding:"12px 14px"}}>
                        <span style={{fontSize:11,fontWeight:600,color:C.accentText}}>
                          {item.source}
                        </span>
                      </td>
                      {/* Category */}
                      <td style={{padding:"12px 14px"}}>
                        <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,
                          background:(CAT_COLORS[item.category]||C.muted)+"20",
                          color:CAT_COLORS[item.category]||C.muted}}>
                          {item.category}
                        </span>
                      </td>
                      {/* Severity */}
                      <td style={{padding:"12px 14px"}}>
                        <span style={{fontSize:11,fontWeight:600,
                          color:SEV_COLORS[item.severity]||C.muted}}>
                          {item.severity}
                        </span>
                      </td>
                      {/* Title + summary */}
                      <td style={{padding:"12px 14px",maxWidth:400}}>
                        <div style={{fontSize:13,fontWeight:600,color:C.white||C.textHi,
                          marginBottom:4,lineHeight:1.4}}>{item.title}</div>
                        <div style={{fontSize:12,color:C.muted,overflow:"hidden",
                          textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:380}}
                          title={item.summary}>
                          {item.summary}
                        </div>
                      </td>
                      {/* Date */}
                      <td style={{padding:"12px 14px",fontSize:11,color:C.muted,whiteSpace:"nowrap"}}>
                        {item.date}
                      </td>
                      {/* Link */}
                      <td style={{padding:"12px 14px"}}>
                        {item.url&&(
                          <a href={item.url} target="_blank" rel="noreferrer"
                            style={{fontSize:11,color:C.accentText,fontWeight:600,
                              display:"flex",alignItems:"center",gap:4,whiteSpace:"nowrap"}}>
                            Read <NavIcon name="externalLink" size={11} color={C.accentText}/>
                          </a>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div style={{padding:"8px 16px",borderTop:`1px solid ${C.border}`,
              fontSize:11,color:C.muted}}>
              {filtered.length} articles · Click source pills above to filter by feed
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── THREAT ACTORS ─────────────────────────────────────────────────────────────
function ThreatActors({token,C}){
  const [query,setQuery]=useState(""); const [result,setResult]=useState(null);
  const [loading,setLoading]=useState(false); const [err,setErr]=useState("");

  const ACTORS=[
    {name:"Lazarus Group",   nation:"🇰🇵",focus:"Financial, Espionage"},
    {name:"APT28",           nation:"🇷🇺",focus:"Government, Military"},
    {name:"APT29",           nation:"🇷🇺",focus:"Government, Think Tanks"},
    {name:"Sandworm",        nation:"🇷🇺",focus:"Critical Infrastructure"},
    {name:"Scattered Spider",nation:"🌐",  focus:"Telecom, Finance"},
    {name:"Volt Typhoon",    nation:"🇨🇳",focus:"Critical Infrastructure"},
    {name:"Carbanak",        nation:"🌐",  focus:"Banking, Finance"},
    {name:"Kimsuky",         nation:"🇰🇵",focus:"Government, Research"},
    {name:"APT41",           nation:"🇨🇳",focus:"Espionage, Cybercrime"},
    {name:"Turla",           nation:"🇷🇺",focus:"Government, Diplomacy"},
    {name:"BlackCat",        nation:"🌐",  focus:"Ransomware"},
    {name:"Cl0p",            nation:"🌐",  focus:"Ransomware, Extortion"},
  ];

  async function research(name){
    const q=name||query.trim();
    if(!q)return;
    setQuery(q);setLoading(true);setErr("");setResult(null);
    const r=await api(`/mitre/actor?name=${encodeURIComponent(q)}`,{},token);
    if(!r.ok){setErr("Failed to reach MITRE ATT&CK.");setLoading(false);return;}
    const d=await r.json();
    if(d.error)setErr(`Error: ${d.error}`);
    else setResult(d);
    setLoading(false);
  }

  return(
    <div style={{maxWidth:1000}}>
      {/* Search bar */}
      <div style={{display:"flex",gap:10,marginBottom:20}}>
        <input value={query} onChange={e=>setQuery(e.target.value)}
          onKeyDown={e=>{if(e.key==="Enter")research();}}
          placeholder="Search any threat actor or APT group..."
          style={{flex:1,background:C.inputBg,border:`1px solid ${C.inputBorder}`,
            color:C.inputText,padding:"10px 14px",borderRadius:10,fontSize:14,
            outline:"none",fontFamily:"inherit"}}/>
        <Btn onClick={()=>research()} disabled={loading||!query.trim()} C={C}>
          {loading?"Searching...":"Search"}
        </Btn>
        {result&&<Btn onClick={()=>{setResult(null);setQuery("");setErr("");}} variant="dim" C={C}>← All Actors</Btn>}
      </div>

      {/* Grid of actor cards — shown when no result selected */}
      {!result&&!loading&&!err&&(
        <>
          <div style={{fontSize:11,color:C.muted,fontWeight:600,letterSpacing:"0.06em",
            textTransform:"uppercase",marginBottom:14}}>
            Known Threat Actors — sourced from MITRE ATT&CK
          </div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(220px,1fr))",gap:12,marginBottom:24}}>
            {ACTORS.map(actor=>(
              <div key={actor.name} onClick={()=>research(actor.name)}
                style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
                  padding:"16px 18px",cursor:"pointer",boxShadow:C.shadow,transition:"all .15s"}}
                onMouseEnter={e=>{e.currentTarget.style.borderColor=C.accent;e.currentTarget.style.boxShadow=C.shadowMd||C.shadow;}}
                onMouseLeave={e=>{e.currentTarget.style.borderColor=C.border;e.currentTarget.style.boxShadow=C.shadow;}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:8}}>
                  <span style={{fontSize:20}}>{actor.nation}</span>
                  <NavIcon name="chevronRight" size={16} color={C.muted}/>
                </div>
                <div style={{fontSize:14,fontWeight:700,color:C.white||C.textHi,marginBottom:4}}>{actor.name}</div>
                <div style={{fontSize:11,color:C.muted}}>{actor.focus}</div>
              </div>
            ))}
          </div>
          <div style={{fontSize:12,color:C.muted,textAlign:"center"}}>
            Click any card or search above for full MITRE ATT&CK profile, TTPs, malware, and references.
          </div>
        </>
      )}

      {loading&&<div style={{textAlign:"center",padding:48,color:C.muted}}>Searching MITRE ATT&CK for <strong style={{color:C.white||C.textHi}}>{query}</strong>...</div>}
      {err&&<div style={{padding:14,background:C.red+"10",border:`1px solid ${C.red}30`,borderRadius:8,color:C.red,fontSize:13}}>{err}</div>}

      {result&&!result.found&&(
        <div style={{textAlign:"center",padding:48,color:C.muted}}>
          <div style={{fontSize:16,fontWeight:600,color:C.white||C.textHi,marginBottom:8}}>Not found in MITRE ATT&CK</div>
          <div style={{fontSize:13,marginBottom:16}}>Try an alternate alias — e.g. "Fancy Bear" instead of "APT28".</div>
          <a href="https://attack.mitre.org/groups/" target="_blank" rel="noreferrer" style={{color:C.accentText,fontSize:12}}>Browse all groups →</a>
        </div>
      )}

      {result?.found&&(
        <div>
          {/* Actor header */}
          <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
            padding:"20px 24px",marginBottom:14,boxShadow:C.shadow}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",
              marginBottom:12,flexWrap:"wrap",gap:12}}>
              <div>
                <div style={{fontSize:24,fontWeight:700,color:C.white||C.textHi,marginBottom:6}}>{result.name}</div>
                {result.also_known_as?.length>0&&(
                  <div style={{fontSize:12,color:C.muted}}>Also known as: {result.also_known_as.join(", ")}</div>
                )}
              </div>
              {result.mitre_url&&(
                <a href={result.mitre_url} target="_blank" rel="noreferrer"
                  style={{fontSize:12,padding:"6px 14px",borderRadius:7,background:C.accentDim,
                    color:C.accentText,fontWeight:600,border:`1px solid ${C.accent}40`,
                    display:"flex",alignItems:"center",gap:6}}>
                  MITRE ATT&CK <NavIcon name="externalLink" size={12} color={C.accentText}/>
                </a>
              )}
            </div>
            {result.description&&(
              <div style={{fontSize:13,color:C.text,lineHeight:1.7,padding:14,
                background:C.surfaceHi,borderRadius:8}}>
                {result.description.slice(0,500)}{result.description.length>500?"...":""}
              </div>
            )}
          </div>

          {/* TTPs */}
          {result.ttps?.length>0&&(
            <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
              padding:"18px 20px",marginBottom:14,boxShadow:C.shadow}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:12,
                letterSpacing:"0.06em",textTransform:"uppercase"}}>
                MITRE ATT&CK Techniques ({result.ttps.length})
              </div>
              <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                {result.ttps.map(t=>(
                  <span key={t} style={{fontSize:11,padding:"3px 10px",borderRadius:4,
                    background:C.purple+"20",color:C.purple,fontWeight:600,
                    border:`1px solid ${C.purple}30`}}>{t}</span>
                ))}
              </div>
            </div>
          )}

          {/* Malware + Tools */}
          {(result.malware_used?.length>0||result.tools_used?.length>0)&&(
            <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
              padding:"18px 20px",marginBottom:14,boxShadow:C.shadow,
              display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))",gap:20}}>
              {result.malware_used?.length>0&&(
                <div>
                  <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:10,
                    textTransform:"uppercase",letterSpacing:"0.06em"}}>Malware Used</div>
                  <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                    {result.malware_used.map(m=>(
                      <span key={m} style={{fontSize:11,padding:"2px 8px",borderRadius:4,
                        background:C.red+"20",color:C.red,border:`1px solid ${C.red}30`}}>{m}</span>
                    ))}
                  </div>
                </div>
              )}
              {result.tools_used?.length>0&&(
                <div>
                  <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:10,
                    textTransform:"uppercase",letterSpacing:"0.06em"}}>Tools Used</div>
                  <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                    {result.tools_used.map(t=>(
                      <span key={t} style={{fontSize:11,padding:"2px 8px",borderRadius:4,
                        background:C.amber+"20",color:C.amber,border:`1px solid ${C.amber}30`}}>{t}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* References */}
          {result.references?.filter(r=>r).length>0&&(
            <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
              padding:"18px 20px",boxShadow:C.shadow}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:12,
                textTransform:"uppercase",letterSpacing:"0.06em"}}>References</div>
              {result.references.filter(r=>r).map((ref,i)=>(
                <a key={i} href={ref} target="_blank" rel="noreferrer"
                  style={{display:"flex",alignItems:"center",gap:6,fontSize:12,
                    color:C.accentText,marginBottom:8,wordBreak:"break-all"}}>
                  <NavIcon name="externalLink" size={11} color={C.accentText}/>{ref}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── OSINT TOOL ────────────────────────────────────────────────────────────────
function OSINTTool({token,C}){
  const [target,setTarget]=useState(""); const [targetType,setTargetType]=useState("domain");
  const [result,setResult]=useState(null); const [loading,setLoading]=useState(false);
  const [activeTab,setActiveTab]=useState("dns");

  async function lookup(){
    if(!target.trim())return;
    setLoading(true);setResult(null);
    const r=await api("/osint/lookup",{method:"POST",body:JSON.stringify({target:target.trim(),target_type:targetType})},token);
    if(r.ok){
      const d=await r.json();
      setResult(d);
      // Auto-select first tab that has data
      const data=d.data||{};
      if(data.dns&&Object.keys(data.dns).length>0) setActiveTab("dns");
      else if(data.rdap) setActiveTab("rdap");
      else if(data.shodan) setActiveTab("shodan");
      else if(data.hibp) setActiveTab("hibp");
    }
    setLoading(false);
  }

  const tabs=result?[
    result.data?.dns&&Object.keys(result.data.dns).length>0    ?{id:"dns",  label:"DNS"}  :null,
    result.data?.rdap                                           ?{id:"rdap", label:"WHOIS"} :null,
    result.data?.shodan                                         ?{id:"shodan",label:"Shodan"}:null,
    result.data?.hibp                                           ?{id:"hibp", label:"HIBP"}  :null,
    result.data?.email_domain_mx?.length>0                      ?{id:"mx",   label:"MX"}    :null,
  ].filter(Boolean):[];

  return(
    <div style={{maxWidth:860}}>
      {/* Input */}
      <div style={{display:"flex",gap:8,marginBottom:20,flexWrap:"wrap"}}>
        <div style={{display:"flex",background:C.surfaceHi,borderRadius:8,padding:3,gap:2,flexShrink:0}}>
          {[["domain","Domain"],["ip","IP"],["email","Email"]].map(([val,label])=>(
            <button key={val} onClick={()=>{setTargetType(val);setResult(null);}}
              style={{padding:"8px 14px",borderRadius:6,border:"none",cursor:"pointer",
                fontSize:12,fontFamily:"inherit",fontWeight:600,
                background:targetType===val?C.accent:"transparent",
                color:targetType===val?"#fff":C.muted}}>
              {label}
            </button>
          ))}
        </div>
        <input value={target} onChange={e=>setTarget(e.target.value)}
          onKeyDown={e=>{if(e.key==="Enter")lookup();}}
          placeholder={targetType==="email"?"email@example.com":targetType==="ip"?"185.220.101.45":"evil-domain.com"}
          style={{flex:1,background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,
            padding:"10px 14px",borderRadius:8,fontSize:14,outline:"none",fontFamily:"inherit"}}/>
        <Btn onClick={lookup} disabled={loading||!target.trim()} C={C}>
          {loading?"Querying...":"Lookup"}
        </Btn>
      </div>

      {loading&&<div style={{textAlign:"center",padding:48,color:C.muted}}>
        <div style={{fontSize:14,marginBottom:8}}>Querying DNS, WHOIS, Shodan...</div>
        <div style={{fontSize:12}}>This may take a few seconds.</div>
      </div>}

      {result&&(
        <>
          {/* Result header */}
          <div style={{marginBottom:16,display:"flex",justifyContent:"space-between",
            alignItems:"center",flexWrap:"wrap",gap:8}}>
            <div>
              <span style={{fontSize:15,fontWeight:700,color:C.white||C.textHi,
                fontFamily:"monospace"}}>{result.target}</span>
              <span style={{fontSize:12,color:C.muted,marginLeft:10}}>
                {new Date(result.queried_at).toLocaleString()}
              </span>
            </div>
          </div>

          {/* Tabs */}
          {tabs.length>0&&(
            <div style={{display:"flex",gap:3,background:C.surfaceHi,borderRadius:10,
              padding:3,width:"fit-content",marginBottom:16}}>
              {tabs.map(t=>(
                <button key={t.id} onClick={()=>setActiveTab(t.id)}
                  style={{padding:"7px 16px",borderRadius:7,border:"none",cursor:"pointer",
                    fontSize:13,fontFamily:"inherit",fontWeight:600,
                    background:activeTab===t.id?C.accent:"transparent",
                    color:activeTab===t.id?"#fff":C.muted}}>
                  {t.label}
                </button>
              ))}
            </div>
          )}

          {/* Tab content */}
          <div style={{background:C.surface,border:`1px solid ${C.border}`,
            borderRadius:12,padding:"18px 20px",boxShadow:C.shadow}}>

            {/* DNS tab */}
            {activeTab==="dns"&&result.data?.dns&&(
              Object.keys(result.data.dns).length===0
                ?<div style={{color:C.muted,fontSize:13}}>No DNS records found.</div>
                :Object.entries(result.data.dns).map(([type,records])=>(
                  <div key={type} style={{marginBottom:16}}>
                    <div style={{fontSize:11,color:C.accentText,fontWeight:700,marginBottom:8,
                      letterSpacing:"0.06em"}}>{type}</div>
                    {records.map((r,i)=>(
                      <div key={i} style={{fontSize:12,color:C.text,padding:"6px 12px",
                        background:C.surfaceHi,borderRadius:6,marginBottom:4,
                        fontFamily:"monospace"}}>{r}</div>
                    ))}
                  </div>
                ))
            )}

            {/* WHOIS tab */}
            {activeTab==="rdap"&&result.data?.rdap&&(
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",gap:16}}>
                {Object.entries(result.data.rdap).filter(([,v])=>v&&v!=="?").map(([k,v])=>(
                  <div key={k}>
                    <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:4,
                      textTransform:"uppercase",letterSpacing:"0.06em"}}>{k.replace(/_/g," ")}</div>
                    <div style={{fontSize:13,color:C.text,fontWeight:500}}>
                      {Array.isArray(v)?v.join(", "):String(v)}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Shodan tab */}
            {activeTab==="shodan"&&result.data?.shodan&&(
              <div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:16,marginBottom:16}}>
                  {[["Org",result.data.shodan.org],["ISP",result.data.shodan.isp],
                    ["Country",result.data.shodan.country],["Last Update",result.data.shodan.last_update]
                  ].filter(([,v])=>v&&v!=="?").map(([k,v])=>(
                    <div key={k}>
                      <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:4,textTransform:"uppercase"}}>{k}</div>
                      <div style={{fontSize:13,color:C.text}}>{v}</div>
                    </div>
                  ))}
                </div>
                {result.data.shodan.ports?.length>0&&(
                  <div style={{marginBottom:14}}>
                    <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:8,textTransform:"uppercase"}}>Open Ports</div>
                    <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                      {result.data.shodan.ports.map(p=>(
                        <span key={p} style={{fontSize:12,padding:"3px 10px",borderRadius:4,
                          background:C.red+"20",color:C.red,fontFamily:"monospace",fontWeight:700}}>{p}</span>
                      ))}
                    </div>
                  </div>
                )}
                {result.data.shodan.vulns?.length>0&&(
                  <div>
                    <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:8,textTransform:"uppercase"}}>Vulnerabilities</div>
                    <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                      {result.data.shodan.vulns.map(v=>(
                        <span key={v} style={{fontSize:12,padding:"3px 10px",borderRadius:4,
                          background:C.amber+"20",color:C.amber,fontFamily:"monospace",fontWeight:600}}>{v}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* HIBP tab */}
            {activeTab==="hibp"&&result.data?.hibp&&(
              result.data.hibp.skipped?(
                <div style={{fontSize:13,color:C.muted,lineHeight:1.8}}>
                  HIBP API key not configured.<br/>
                  Add <code style={{color:C.accentText}}>HIBP_API_KEY</code> to <code style={{color:C.accentText}}>.env</code>.{" "}
                  <a href="https://haveibeenpwned.com/API/Key" target="_blank" rel="noreferrer"
                    style={{color:C.accentText}}>Get a free key →</a>
                </div>
              ):result.data.hibp.breached?(
                <>
                  <div style={{fontSize:14,fontWeight:700,color:C.red,marginBottom:14}}>
                    ⚠ Found in {result.data.hibp.breach_count} data breach{result.data.hibp.breach_count!==1?"es":""}
                  </div>
                  {result.data.hibp.breaches?.map(b=>(
                    <div key={b.name} style={{background:C.surfaceHi,border:`1px solid ${C.border}`,
                      borderRadius:8,padding:12,marginBottom:8}}>
                      <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                        <span style={{fontSize:13,fontWeight:700,color:C.white||C.textHi}}>{b.name}</span>
                        <span style={{fontSize:11,color:C.muted}}>{b.date}</span>
                      </div>
                      <div style={{display:"flex",flexWrap:"wrap",gap:4}}>
                        {b.data_classes?.map(dc=>(
                          <span key={dc} style={{fontSize:10,padding:"2px 7px",borderRadius:3,
                            background:C.red+"20",color:C.red,fontWeight:600}}>{dc}</span>
                        ))}
                      </div>
                    </div>
                  ))}
                </>
              ):<div style={{fontSize:13,color:C.green,fontWeight:600}}>✓ Not found in any known data breaches</div>
            )}

            {/* MX tab */}
            {activeTab==="mx"&&result.data?.email_domain_mx?.length>0&&(
              <div>
                <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:10,textTransform:"uppercase"}}>MX Records</div>
                {result.data.email_domain_mx.map((mx,i)=>(
                  <div key={i} style={{fontSize:12,color:C.text,padding:"6px 12px",
                    background:C.surfaceHi,borderRadius:6,marginBottom:4,fontFamily:"monospace"}}>{mx}</div>
                ))}
              </div>
            )}

            {tabs.length===0&&(
              <div style={{textAlign:"center",padding:24,color:C.muted,fontSize:13}}>
                No data returned. Check your target and type.
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

// ── GLOBAL SEARCH ─────────────────────────────────────────────────────────────
// ── SPL / KQL GENERATOR ───────────────────────────────────────────────────────
function QueryGenerator({token,C}){
  const [mode,setMode]=useState("builder"); // builder | explainer
  const [useCase,setUseCase]=useState("");
  const [context,setContext]=useState("");
  const [tacticHint,setTacticHint]=useState("");
  const [queryType,setQueryType]=useState("kql");
  const [result,setResult]=useState(null);
  const [activeVariant,setActiveVariant]=useState(0);
  const [loading,setLoading]=useState(false);
  const [err,setErr]=useState("");
  const [copied,setCopied]=useState(false);

  // Explainer state
  const [explainQuery,setExplainQuery]=useState("");
  const [explainResult,setExplainResult]=useState(null);
  const [explaining,setExplaining]=useState(false);
  const [explainErr,setExplainErr]=useState("");

  const TACTICS=["","Initial Access","Execution","Persistence","Privilege Escalation",
    "Defense Evasion","Credential Access","Discovery","Lateral Movement",
    "Collection","Exfiltration","Command & Control","Impact"];

  const SEV_COLORS={Critical:C.red,High:C.amber,Medium:C.purple,Low:C.green};
  const CONF_COLORS={85:C.green,70:C.amber,50:C.muted};

  async function generate(){
    if(!useCase.trim()) return;
    setLoading(true);setErr("");setResult(null);setActiveVariant(0);
    try{
      const r=await api("/query-gen/generate",{method:"POST",
        body:JSON.stringify({use_case:useCase,query_type:queryType,
          context,tactic_hint:tacticHint})},token);
      if(r.ok) setResult(await r.json());
      else {const e=await r.json();setErr(e.detail||"Generation failed");}
    }catch{setErr("Cannot reach server.");}
    setLoading(false);
  }

  async function explain(){
    if(!explainQuery.trim()) return;
    setExplaining(true);setExplainErr("");setExplainResult(null);
    try{
      const r=await api("/query-gen/explain",{method:"POST",
        body:JSON.stringify({query:explainQuery,query_type:queryType})},token);
      if(r.ok) setExplainResult(await r.json());
      else {const e=await r.json();setExplainErr(e.detail||"Failed");}
    }catch{setExplainErr("Cannot reach server.");}
    setExplaining(false);
  }

  function copyQuery(q){
    navigator.clipboard.writeText(q);setCopied(true);
    setTimeout(()=>setCopied(false),2000);
  }

  const variant=result?.queries?.[activeVariant];
  const CONF_COLOR=c=>c>=80?C.green:c>=60?C.amber:C.muted;

  return(
    <div style={{maxWidth:960}}>
      {/* Mode + Platform Switcher */}
      <div style={{display:"flex",gap:12,marginBottom:20,flexWrap:"wrap",alignItems:"center"}}>
        <div style={{display:"flex",background:C.surfaceHi,borderRadius:10,padding:3,gap:2}}>
          {[["builder","⚡ Builder"],["explainer","🔍 Explainer"]].map(([id,label])=>(
            <button key={id} onClick={()=>setMode(id)}
              style={{padding:"8px 18px",borderRadius:8,border:"none",cursor:"pointer",
                fontSize:13,fontFamily:"inherit",fontWeight:600,
                background:mode===id?C.accent:"transparent",color:mode===id?"#fff":C.muted}}>
              {label}
            </button>
          ))}
        </div>
        <div style={{display:"flex",background:C.surfaceHi,borderRadius:10,padding:3,gap:2}}>
          {[["kql","KQL / Sentinel"],["spl","SPL / Splunk"]].map(([id,label])=>(
            <button key={id} onClick={()=>setQueryType(id)}
              style={{padding:"7px 16px",borderRadius:8,border:"none",cursor:"pointer",
                fontSize:12,fontFamily:"inherit",fontWeight:600,
                background:queryType===id?C.purple:"transparent",color:queryType===id?"#fff":C.muted}}>
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* ── BUILDER MODE ── */}
      {mode==="builder"&&(
        <div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
            <div style={{gridColumn:"1/-1"}}>
              <Field label="Describe what you want to detect *" C={C}>
                <textarea value={useCase} onChange={e=>setUseCase(e.target.value)}
                  onKeyDown={e=>{if(e.key==="Enter"&&(e.ctrlKey||e.metaKey))generate();}}
                  placeholder={queryType==="kql"
                    ?"e.g. Detect PowerShell downloading a file from the internet using Invoke-WebRequest or WebClient — flag processes spawned from Office apps, exclude known AV paths"
                    :"e.g. Detect brute force login attempts — more than 10 failed authentications within 5 minutes from the same source IP, followed by a successful login"}
                  rows={4}
                  style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                    color:C.inputText,padding:"10px 12px",borderRadius:8,fontSize:13,
                    outline:"none",fontFamily:"inherit",resize:"vertical",boxSizing:"border-box"}}/>
              </Field>
            </div>
            <Field label={`MITRE Tactic (optional)`} C={C}>
              <select value={tacticHint} onChange={e=>setTacticHint(e.target.value)}
                style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                  color:C.inputText,padding:"10px 12px",borderRadius:8,fontSize:13,
                  outline:"none",fontFamily:"inherit"}}>
                {TACTICS.map(t=><option key={t} value={t}>{t||"— Any —"}</option>)}
              </select>
            </Field>
            <Field label="Environment context (optional)" C={C}>
              <Inp value={context} onChange={setContext}
                placeholder="e.g. Azure AD P2, MDE deployed, no EDR on servers" C={C}/>
            </Field>
          </div>
          <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:20}}>
            <Btn onClick={generate} disabled={loading||!useCase.trim()} C={C}>
              {loading?"Generating production queries...":"⚡ Generate Detection Queries"}
            </Btn>
            <span style={{fontSize:11,color:C.muted}}>Ctrl+Enter in description box also works</span>
          </div>

          {err&&<div style={{padding:"10px 14px",background:C.red+"10",border:`1px solid ${C.red}30`,
            borderRadius:8,color:C.red,fontSize:13,marginBottom:16}}>{err}</div>}

          {loading&&(
            <div style={{textAlign:"center",padding:60,color:C.muted}}>
              <div style={{fontSize:14,fontWeight:600,color:C.white||C.textHi,marginBottom:8}}>
                Writing production-grade detection queries...
              </div>
              <div style={{fontSize:12}}>Building 3 variants: High Fidelity → Balanced → Threat Hunting</div>
            </div>
          )}

          {result&&(
            <div>
              {/* Variant tabs */}
              <div style={{display:"flex",gap:3,background:C.surfaceHi,borderRadius:10,
                padding:3,marginBottom:16,width:"fit-content"}}>
                {result.queries?.map((q,i)=>(
                  <button key={i} onClick={()=>setActiveVariant(i)}
                    style={{padding:"8px 18px",borderRadius:8,border:"none",cursor:"pointer",
                      fontSize:13,fontFamily:"inherit",fontWeight:600,
                      background:activeVariant===i?C.accent:"transparent",
                      color:activeVariant===i?"#fff":C.muted}}>
                    {q.label}
                  </button>
                ))}
              </div>

              {variant&&(
                <div style={{display:"grid",gridTemplateColumns:"2fr 1fr",gap:14}}>
                  {/* Left: Query */}
                  <div>
                    <div style={{background:C.surface,border:`1px solid ${C.border}`,
                      borderRadius:12,overflow:"hidden",boxShadow:C.shadow}}>
                      {/* Query header */}
                      <div style={{padding:"12px 16px",borderBottom:`1px solid ${C.border}`,
                        display:"flex",justifyContent:"space-between",alignItems:"center",
                        background:C.surfaceHi}}>
                        <div style={{display:"flex",gap:10,alignItems:"center"}}>
                          <span style={{fontSize:12,fontWeight:700,color:C.white||C.textHi}}>
                            {variant.label}
                          </span>
                          <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:600,
                            background:(SEV_COLORS[variant.severity]||C.muted)+"20",
                            color:SEV_COLORS[variant.severity]||C.muted}}>
                            {variant.severity}
                          </span>
                          <span style={{fontSize:11,color:CONF_COLOR(variant.confidence||0),fontWeight:600}}>
                            {variant.confidence||"—"}% confidence
                          </span>
                        </div>
                        <button onClick={()=>copyQuery(variant.query)}
                          style={{fontSize:11,padding:"5px 12px",borderRadius:6,cursor:"pointer",
                            background:copied?C.green+"20":C.accentDim,
                            border:`1px solid ${copied?C.green:C.accent}40`,
                            color:copied?C.green:C.accentText,fontWeight:600,fontFamily:"inherit"}}>
                          {copied?"✓ Copied":"Copy Query"}
                        </button>
                      </div>
                      {/* Query body */}
                      <div style={{padding:16,overflowX:"auto"}}>
                        <pre style={{margin:0,fontSize:11,color:C.text,lineHeight:1.6,
                          fontFamily:"'JetBrains Mono','Fira Code',monospace",
                          whiteSpace:"pre-wrap",wordBreak:"break-word"}}>
                          {variant.query}
                        </pre>
                      </div>
                      {variant.description&&(
                        <div style={{padding:"10px 16px",borderTop:`1px solid ${C.border}`,
                          fontSize:12,color:C.muted,background:C.surfaceHi}}>
                          {variant.description}
                        </div>
                      )}
                    </div>
                    {/* Schedule */}
                    {variant.schedule&&(
                      <div style={{marginTop:8,padding:"8px 12px",background:C.accentDim,
                        border:`1px solid ${C.accent}30`,borderRadius:8,
                        fontSize:11,color:C.accentText}}>
                        🕐 Recommended schedule: {variant.schedule}
                      </div>
                    )}
                  </div>

                  {/* Right: Metadata */}
                  <div style={{display:"flex",flexDirection:"column",gap:12}}>
                    {/* MITRE */}
                    {result.mitre&&(
                      <div style={{background:C.surface,border:`1px solid ${C.border}`,
                        borderRadius:10,padding:"14px 16px",boxShadow:C.shadow}}>
                        <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:8,
                          textTransform:"uppercase",letterSpacing:"0.05em"}}>MITRE ATT&CK</div>
                        <div style={{fontSize:12,color:C.red,fontWeight:700,marginBottom:4}}>
                          {result.mitre.technique}
                        </div>
                        <div style={{fontSize:12,color:C.white||C.textHi,fontWeight:600,marginBottom:4}}>
                          {result.mitre.technique_name}
                        </div>
                        <div style={{fontSize:11,color:C.muted,marginBottom:8}}>{result.mitre.tactic}</div>
                        {result.mitre.url&&(
                          <a href={result.mitre.url} target="_blank" rel="noreferrer"
                            style={{fontSize:11,color:C.accentText,display:"flex",alignItems:"center",gap:4}}>
                            <NavIcon name="externalLink" size={10} color={C.accentText}/>View on MITRE
                          </a>
                        )}
                      </div>
                    )}

                    {/* Required tables */}
                    {(result.required_tables||result.required_indexes)?.length>0&&(
                      <div style={{background:C.surface,border:`1px solid ${C.border}`,
                        borderRadius:10,padding:"14px 16px",boxShadow:C.shadow}}>
                        <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:8,
                          textTransform:"uppercase",letterSpacing:"0.05em"}}>
                          Required {queryType==="kql"?"Tables":"Indexes"}
                        </div>
                        {(result.required_tables||result.required_indexes||[]).map(t=>(
                          <div key={t} style={{fontSize:11,color:C.text,padding:"3px 0",
                            fontFamily:"monospace"}}>{t}</div>
                        ))}
                        {(result.required_connectors||result.required_sourcetypes||[]).map(t=>(
                          <div key={t} style={{fontSize:10,color:C.muted,marginTop:2}}>→ {t}</div>
                        ))}
                      </div>
                    )}

                    {/* False positives */}
                    {result.false_positives?.length>0&&(
                      <div style={{background:C.surface,border:`1px solid ${C.amber}30`,
                        borderRadius:10,padding:"14px 16px",boxShadow:C.shadow}}>
                        <div style={{fontSize:10,color:C.amber,fontWeight:600,marginBottom:8,
                          textTransform:"uppercase",letterSpacing:"0.05em"}}>⚠ False Positives</div>
                        {result.false_positives.map((fp,i)=>(
                          <div key={i} style={{fontSize:11,color:C.text,marginBottom:4,
                            lineHeight:1.5}}>• {fp}</div>
                        ))}
                      </div>
                    )}

                    {/* Tuning tips */}
                    {result.tuning_tips?.length>0&&(
                      <div style={{background:C.surface,border:`1px solid ${C.border}`,
                        borderRadius:10,padding:"14px 16px",boxShadow:C.shadow}}>
                        <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:8,
                          textTransform:"uppercase",letterSpacing:"0.05em"}}>Tuning Tips</div>
                        {result.tuning_tips.map((tip,i)=>(
                          <div key={i} style={{fontSize:11,color:C.text,marginBottom:4,
                            lineHeight:1.5}}>• {tip}</div>
                        ))}
                      </div>
                    )}

                    {/* Performance */}
                    {result.performance&&(
                      <div style={{fontSize:11,color:C.muted,padding:"8px 12px",
                        background:C.surfaceHi,borderRadius:8,lineHeight:1.5}}>
                        ⚡ {result.performance}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── EXPLAINER MODE ── */}
      {mode==="explainer"&&(
        <div>
          <Field label={`Paste a ${queryType==="kql"?"KQL":"SPL"} query to explain *`} C={C}>
            <textarea value={explainQuery} onChange={e=>setExplainQuery(e.target.value)}
              placeholder={queryType==="kql"
                ?"Paste any KQL query here — Sentinel analytics rule, hunting query, or custom detection..."
                :"Paste any SPL search here — ES correlation search, dashboard query, or custom search..."}
              rows={8}
              style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                color:C.inputText,padding:"12px",borderRadius:8,fontSize:12,
                outline:"none",fontFamily:"'JetBrains Mono','Fira Code',monospace",
                resize:"vertical",lineHeight:1.6,boxSizing:"border-box"}}/>
          </Field>
          <div style={{display:"flex",gap:8,marginBottom:20,marginTop:10}}>
            <Btn onClick={explain} disabled={explaining||!explainQuery.trim()} C={C}>
              {explaining?"Analyzing query...":"🔍 Explain This Query"}
            </Btn>
            {explainResult&&<Btn onClick={()=>{setExplainResult(null);setExplainQuery("");}} variant="dim" C={C}>Clear</Btn>}
          </div>

          {explainErr&&<div style={{padding:"10px 14px",background:C.red+"10",border:`1px solid ${C.red}30`,
            borderRadius:8,color:C.red,fontSize:13,marginBottom:16}}>{explainErr}</div>}

          {explaining&&(
            <div style={{textAlign:"center",padding:48,color:C.muted}}>
              <div style={{fontSize:14,fontWeight:600,color:C.white||C.textHi,marginBottom:8}}>Analyzing query...</div>
              <div style={{fontSize:12}}>Breaking down each clause, identifying the threat pattern, checking for improvements</div>
            </div>
          )}

          {explainResult&&(
            <div>
              {/* Summary card */}
              <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
                padding:"18px 20px",marginBottom:14,boxShadow:C.shadow}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",
                  gap:12,flexWrap:"wrap",marginBottom:12}}>
                  <div style={{flex:1}}>
                    <div style={{fontSize:15,fontWeight:700,color:C.white||C.textHi,marginBottom:6,lineHeight:1.4}}>
                      {explainResult.summary}
                    </div>
                    <div style={{fontSize:13,color:C.text,lineHeight:1.7}}>
                      {explainResult.threat_description}
                    </div>
                  </div>
                  <div style={{display:"flex",gap:8,flexShrink:0,flexWrap:"wrap"}}>
                    {explainResult.severity&&(
                      <span style={{fontSize:12,padding:"4px 12px",borderRadius:6,fontWeight:700,
                        background:(SEV_COLORS[explainResult.severity]||C.muted)+"20",
                        color:SEV_COLORS[explainResult.severity]||C.muted}}>
                        {explainResult.severity}
                      </span>
                    )}
                    {explainResult.mitre?.technique&&(
                      <a href={explainResult.mitre?.url||"#"} target="_blank" rel="noreferrer"
                        style={{fontSize:11,padding:"4px 10px",borderRadius:6,fontWeight:600,
                          background:C.purple+"20",color:C.purple,border:`1px solid ${C.purple}30`,
                          textDecoration:"none"}}>
                        {explainResult.mitre.technique}
                      </a>
                    )}
                  </div>
                </div>
                {explainResult.estimated_fidelity&&(
                  <div style={{fontSize:11,color:C.muted,padding:"6px 10px",background:C.surfaceHi,
                    borderRadius:6,display:"inline-block"}}>
                    Estimated fidelity: {explainResult.estimated_fidelity}
                  </div>
                )}
              </div>

              {/* Line-by-line */}
              {explainResult.line_by_line?.length>0&&(
                <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
                  overflow:"hidden",marginBottom:14,boxShadow:C.shadow}}>
                  <div style={{padding:"12px 16px",background:C.surfaceHi,
                    borderBottom:`1px solid ${C.border}`,fontSize:11,fontWeight:600,
                    color:C.muted,textTransform:"uppercase",letterSpacing:"0.05em"}}>
                    Line-by-Line Breakdown
                  </div>
                  {explainResult.line_by_line.map((line,i)=>(
                    <div key={i} style={{display:"grid",gridTemplateColumns:"1fr 1fr",
                      borderBottom:i<explainResult.line_by_line.length-1?`1px solid ${C.border}20`:"none"}}>
                      <div style={{padding:"10px 16px",background:C.surfaceHi+"60",
                        borderRight:`1px solid ${C.border}`}}>
                        <code style={{fontSize:11,color:C.accentText,fontFamily:"monospace",
                          lineHeight:1.5,whiteSpace:"pre-wrap",wordBreak:"break-word"}}>
                          {line.code}
                        </code>
                      </div>
                      <div style={{padding:"10px 16px",fontSize:12,color:C.text,lineHeight:1.6}}>
                        {line.explanation}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* 3-column detail grid */}
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(240px,1fr))",gap:12,marginBottom:14}}>
                {explainResult.what_it_catches?.length>0&&(
                  <div style={{background:C.surface,border:`1px solid ${C.green}30`,borderRadius:10,padding:"14px 16px"}}>
                    <div style={{fontSize:10,color:C.green,fontWeight:600,marginBottom:8,textTransform:"uppercase"}}>✓ What It Catches</div>
                    {explainResult.what_it_catches.map((w,i)=>(
                      <div key={i} style={{fontSize:11,color:C.text,marginBottom:4,lineHeight:1.5}}>• {w}</div>
                    ))}
                  </div>
                )}
                {explainResult.what_it_misses?.length>0&&(
                  <div style={{background:C.surface,border:`1px solid ${C.amber}30`,borderRadius:10,padding:"14px 16px"}}>
                    <div style={{fontSize:10,color:C.amber,fontWeight:600,marginBottom:8,textTransform:"uppercase"}}>✗ What It Misses</div>
                    {explainResult.what_it_misses.map((w,i)=>(
                      <div key={i} style={{fontSize:11,color:C.text,marginBottom:4,lineHeight:1.5}}>• {w}</div>
                    ))}
                  </div>
                )}
                {explainResult.false_positives?.length>0&&(
                  <div style={{background:C.surface,border:`1px solid ${C.red}20`,borderRadius:10,padding:"14px 16px"}}>
                    <div style={{fontSize:10,color:C.red,fontWeight:600,marginBottom:8,textTransform:"uppercase"}}>⚠ False Positives</div>
                    {explainResult.false_positives.map((fp,i)=>(
                      <div key={i} style={{fontSize:11,color:C.text,marginBottom:4,lineHeight:1.5}}>• {fp}</div>
                    ))}
                  </div>
                )}
              </div>

              {/* Improvements */}
              {explainResult.improvements?.length>0&&(
                <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:"16px 18px"}}>
                  <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:12,
                    textTransform:"uppercase",letterSpacing:"0.05em"}}>
                    🛠 Improvement Suggestions
                  </div>
                  {explainResult.improvements.map((imp,i)=>(
                    <div key={i} style={{marginBottom:12,padding:"10px 14px",background:C.surfaceHi,borderRadius:8}}>
                      <div style={{fontSize:12,fontWeight:700,color:C.amber,marginBottom:4}}>
                        Issue: {imp.issue}
                      </div>
                      <div style={{fontSize:12,color:C.text,lineHeight:1.6}}>
                        <span style={{color:C.green,fontWeight:600}}>Fix: </span>{imp.fix}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function GlobalSearch({token,C,onSelect,onCVELookup}){
  const [q,setQ]=useState(""); const [results,setResults]=useState(null);
  const [loading,setLoading]=useState(false); const [open,setOpen]=useState(false);
  const ref=useRef(null);
  const CVE_RE=/^CVE-\d{4}-\d{4,}$/i;
  const isCVE = CVE_RE.test(q.trim());

  useEffect(()=>{const h=e=>{if(ref.current&&!ref.current.contains(e.target))setOpen(false);};document.addEventListener("mousedown",h);return()=>document.removeEventListener("mousedown",h);},[]);

  async function search(){
    if(!q.trim())return;
    // If it's a CVE ID, route to CVE lookup instead of IOC search
    if(isCVE){
      onCVELookup&&onCVELookup(q.trim().toUpperCase());
      setOpen(false);setQ("");return;
    }
    setLoading(true);setOpen(true);
    const r=await api(`/iocs/search?q=${encodeURIComponent(q)}`,{},token);
    if(r.ok)setResults(await r.json());
    setLoading(false);
  }

  return(
    <div ref={ref} style={{position:"relative",maxWidth:440,width:"100%"}}>
      <div style={{display:"flex",gap:6}}>
        <input value={q} onChange={e=>setQ(e.target.value)}
          onKeyDown={e=>{if(e.key==="Enter")search();}}
          placeholder={isCVE?"Press Enter to look up this CVE across all sources...":"Global IOC search or CVE-XXXX-XXXX..."}
          style={{flex:1,background:C.inputBg,
            border:`1px solid ${isCVE?C.accent:C.inputBorder}`,
            color:C.inputText,padding:"8px 14px",borderRadius:8,fontSize:13,
            outline:"none",fontFamily:isCVE?"monospace":"inherit",
            boxShadow:isCVE?`0 0 0 2px ${C.accent}20`:"none"}}/>
        <button onClick={search}
          style={{padding:"8px 16px",background:isCVE?C.green:C.accent,
            border:"none",color:"#fff",borderRadius:8,cursor:"pointer",fontSize:14,fontWeight:700}}>
          {isCVE?"⟳":"⌕"}
        </button>
      </div>
      {isCVE&&q.trim()&&(
        <div style={{position:"absolute",top:"calc(100% + 6px)",left:0,right:0,zIndex:300,
          background:C.surface,border:`1px solid ${C.accent}40`,borderRadius:10,
          boxShadow:C.shadow,padding:"12px 14px",cursor:"pointer"}}
          onClick={()=>{onCVELookup&&onCVELookup(q.trim().toUpperCase());setOpen(false);setQ("");}}>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <span style={{fontSize:20}}>🔍</span>
            <div>
              <div style={{fontSize:13,fontWeight:700,color:C.white||C.textHi}}>
                Look up {q.trim().toUpperCase()} across all sources
              </div>
              <div style={{fontSize:11,color:C.muted}}>
                NVD · CVE.org · OSV · CVE Trends · EPSS · CISA KEV
              </div>
            </div>
          </div>
        </div>
      )}
      {open&&!isCVE&&(
        <div style={{position:"absolute",top:"calc(100% + 6px)",left:0,right:0,zIndex:300,background:C.surface,border:`1px solid ${C.border}`,borderRadius:10,boxShadow:C.shadow,maxHeight:360,overflowY:"auto"}}>
          {loading&&<div style={{padding:16,fontSize:13,color:C.muted}}>Searching...</div>}
          {!loading&&results&&(<>
            <div style={{padding:"8px 14px",fontSize:11,color:C.muted,borderBottom:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between"}}>
              <span>{results.count} result{results.count!==1?"s":""}</span>
              <button onClick={()=>setOpen(false)} style={{background:"none",border:"none",color:C.muted,cursor:"pointer"}}>×</button>
            </div>
            {results.count===0&&<div style={{padding:16,fontSize:13,color:C.muted}}>No IOCs found.</div>}
            {results.results?.map(ioc=>(
              <div key={ioc.id} onClick={()=>{onSelect(ioc);setOpen(false);}} style={{padding:"12px 14px",cursor:"pointer",borderBottom:`1px solid ${C.border}20`}}
                onMouseEnter={e=>e.currentTarget.style.background=C.surfaceHi} onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:3,flexWrap:"wrap"}}>
                  <span style={{fontSize:11,padding:"1px 6px",borderRadius:3,background:C.badge||C.surfaceHi,color:C.accentText,fontWeight:700}}>{ioc.type}</span>
                  <span style={{fontSize:13,color:C.white||C.textHi,fontWeight:500}}>{ioc.value_defanged||ioc.value}</span>
                  <TLPBadge level={ioc.tlp}/>
                </div>
                <div style={{fontSize:11,color:C.muted}}>{ioc.industry} · conf {ioc.confidence}</div>
              </div>
            ))}
          </>)}
        </div>
      )}
    </div>
  );
}

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
function Dashboard({token,C}){
  const [stats,setStats]=useState(null);
  const [open,setOpen]=useState({charts:false,api:false}); // collapsed by default
  const toggle=k=>setOpen(p=>({...p,[k]:!p[k]}));

  useEffect(()=>{api("/stats/dashboard",{},token).then(r=>r.ok?r.json():null).then(d=>{if(d)setStats(d);});},[token]);

  if(!stats)return(
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",gap:14,marginBottom:24}}>
      {[1,2,3,4].map(i=>(
        <div key={i} style={{background:C.surface,border:`1px solid ${C.border}`,
          borderRadius:12,padding:"22px 24px",height:90,opacity:.5}}/>
      ))}
    </div>
  );

  const VT_LIMIT=500,ABUSE_LIMIT=1000;
  const vtPct=Math.min(100,Math.round((stats.api_usage?.virustotal||0)/VT_LIMIT*100));
  const abusePct=Math.min(100,Math.round((stats.api_usage?.abuseipdb||0)/ABUSE_LIMIT*100));
  const highConf=stats.by_confidence?.find(x=>x.band==="High")?.count||0;

  const CollapsibleSection=({id,title,children})=>(
    <div style={{marginBottom:16}}>
      <button onClick={()=>toggle(id)}
        style={{display:"flex",justifyContent:"space-between",alignItems:"center",
          width:"100%",padding:"12px 16px",background:C.surface,
          border:`1px solid ${C.border}`,borderRadius:open[id]?`10px 10px 0 0`:"10px",
          cursor:"pointer",fontFamily:"inherit",color:C.text,
          borderBottom:open[id]?`1px solid ${C.border}`:"none"}}>
        <span style={{fontSize:12,fontWeight:600,letterSpacing:"0.04em",
          textTransform:"uppercase",color:C.muted}}>{title}</span>
        <span style={{fontSize:14,color:C.muted,transition:"transform .2s",
          display:"inline-block",transform:open[id]?"rotate(180deg)":"rotate(0deg)"}}>▾</span>
      </button>
      {open[id]&&(
        <div style={{background:C.surface,border:`1px solid ${C.border}`,
          borderTop:"none",borderRadius:`0 0 10px 10px`,padding:"16px"}}>
          {children}
        </div>
      )}
    </div>
  );

  return(
    <div>
      <div style={{marginBottom:20,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <h2 style={{fontSize:18,fontWeight:700,color:C.white||C.textHi,margin:0,letterSpacing:"-0.02em"}}>
          IOC Insights
        </h2>
      </div>

      {/* Big stat cards — always visible */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(180px,1fr))",gap:12,marginBottom:20}}>
        <StatCard label="Live IOCs"        value={stats.total}   sublabel="IOCs" color={C.accent}  C={C}/>
        <StatCard label="High Confidence"  value={highConf}      sublabel="IOCs" color={C.green}   C={C}/>
        <StatCard label="Expired"          value={stats.expired} sublabel="IOCs" color={C.amber}   C={C}/>
        <StatCard label="False Positives"  value={stats.fp_count}sublabel="IOCs" color={C.red}     C={C}/>
      </div>

      {/* Collapsible: Breakdowns */}
      <CollapsibleSection id="charts" title="Breakdown by Type, Industry, TLP, Analyst">
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))",gap:16}}>
          {[
            {title:"By Type",      data:stats.by_type,         key:"type"},
            {title:"By Industry",  data:stats.by_industry,     key:"industry"},
            {title:"By TLP",       data:stats.by_tlp,          key:"tlp"},
            {title:"Top Analysts", data:stats.top_contributors,key:"username"},
          ].map(({title,data,key})=>(
            <div key={title}>
              <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:12,
                textTransform:"uppercase",letterSpacing:"0.05em"}}>{title}</div>
              {(data||[]).slice(0,6).map((row,i)=>{
                const max=Math.max(...(data||[]).map(x=>x.count),1);
                return(
                  <div key={i} style={{marginBottom:9}}>
                    <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                      <span style={{fontSize:12,color:C.text,fontWeight:500}}>
                        {key==="tlp"?<TLPBadge level={row[key]}/>:row[key]||"unknown"}
                      </span>
                      <span style={{fontSize:12,color:C.muted}}>{row.count}</span>
                    </div>
                    <div style={{height:3,background:C.border,borderRadius:4,overflow:"hidden"}}>
                      <div style={{width:`${(row.count/max)*100}%`,height:"100%",
                        background:C.accent,borderRadius:4}}/>
                    </div>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </CollapsibleSection>

      {/* Collapsible: API usage */}
      <CollapsibleSection id="api" title="Platform API Usage Today">
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:16,marginBottom:12}}>
          {[
            {name:"VirusTotal",used:stats.api_usage?.virustotal||0,limit:VT_LIMIT,   pct:vtPct},
            {name:"AbuseIPDB", used:stats.api_usage?.abuseipdb||0, limit:ABUSE_LIMIT,pct:abusePct},
            {name:"URLhaus",   used:stats.api_usage?.urlhaus||0,   limit:"∞",        pct:0},
          ].map(({name,used,limit,pct})=>(
            <div key={name}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}>
                <span style={{fontSize:13,color:C.text,fontWeight:500}}>{name}</span>
                <span style={{fontSize:12,fontWeight:600,
                  color:pct>=80?C.red:pct>=60?C.amber:C.green}}>
                  {used}{limit!=="∞"?`/${limit}`:""}
                </span>
              </div>
              {limit!=="∞"&&(
                <div style={{height:4,background:C.border,borderRadius:4,overflow:"hidden"}}>
                  <div style={{width:`${pct}%`,height:"100%",borderRadius:4,
                    background:pct>=80?C.red:pct>=60?C.amber:C.accent}}/>
                </div>
              )}
              {limit==="∞"&&<div style={{fontSize:11,color:C.muted}}>No rate limit</div>}
            </div>
          ))}
        </div>
        <div style={{fontSize:12,color:C.muted,borderTop:`1px solid ${C.border}`,paddingTop:10}}>
          Cache hits today: <span style={{color:C.green,fontWeight:600}}>{stats.api_usage?.cache_hits_today||0}</span>
          {" "}— enrichments cached 24h to preserve API quota.
        </div>
      </CollapsibleSection>
    </div>
  );
}


// ── SETTINGS ──────────────────────────────────────────────────────────────────
// ── API KEY SETUP MODAL (shown after login) ───────────────────────────────────
function ApiKeyModal({token, C, onClose}){
  const [keys,setKeys]=useState({});
  const [saving,setSaving]=useState({});
  const [saved,setSaved]=useState({});
  const [existingKeys,setExistingKeys]=useState({});
  const [quota,setQuota]=useState(null);

  const SERVICES=[
    {id:"virustotal", name:"VirusTotal",    url:"https://www.virustotal.com/gui/my-apikey",       desc:"Malware & IP reputation",     placeholder:"Enter your VT API key"},
    {id:"abuseipdb",  name:"AbuseIPDB",     url:"https://www.abuseipdb.com/account/api",          desc:"IP abuse confidence scoring",  placeholder:"Enter your AbuseIPDB key"},
    {id:"groq",       name:"Groq",          url:"https://console.groq.com/keys",                  desc:"SPL/KQL query generation",     placeholder:"gsk_xxxxxxxxxxxx"},
    {id:"shodan",     name:"Shodan",        url:"https://account.shodan.io/",                     desc:"Port scan & host lookup",      placeholder:"Enter your Shodan key"},
    {id:"hibp",       name:"HaveIBeenPwned",url:"https://haveibeenpwned.com/API/Key",              desc:"Email breach lookup",          placeholder:"Enter your HIBP key"},
    {id:"nvd",        name:"NVD",           url:"https://nvd.nist.gov/developers/request-an-api-key","desc":"CVE database (higher rate limit)","placeholder":"Enter your NVD key"},
  ];

  useEffect(()=>{
    // Load existing keys so we don't prompt for ones already saved
    api("/users/me/api-keys",{},token).then(r=>r.ok?r.json():null).then(d=>{
      if(d){
        const existing={};
        d.forEach(k=>{ if(k.has_key) existing[k.service]=true; });
        setExistingKeys(existing);
      }
    }).catch(()=>{});
    api("/users/me/quota",{},token).then(r=>r.ok?r.json():null).then(q=>{if(q)setQuota(q);});
  },[token]);

  async function saveKey(svc){
    const k=keys[svc]?.trim();
    if(!k)return;
    setSaving(p=>({...p,[svc]:true}));
    const r=await api(`/users/me/api-keys/${svc}`,{method:"POST",body:JSON.stringify({api_key:k})},token);
    if(r.ok){setSaved(p=>({...p,[svc]:true}));setKeys(p=>({...p,[svc]:""}));}
    setSaving(p=>({...p,[svc]:false}));
  }

  const anyQuotaLow = quota && Object.values(quota).some(q=>!q.unlimited && q.quota_remaining<=3);

  return(
    <div style={{position:"fixed",inset:0,background:"#000000b0",display:"flex",
      alignItems:"center",justifyContent:"center",zIndex:700,padding:16}}>
      <div style={{width:"100%",maxWidth:560,maxHeight:"92vh",overflowY:"auto",
        background:C.surface,border:`1px solid ${C.border}`,borderRadius:16,
        boxShadow:C.shadow,fontFamily:C.font||"inherit"}}>

        {/* Header */}
        <div style={{padding:"24px 24px 0"}}>
          <div style={{fontSize:18,fontWeight:700,color:C.white,marginBottom:6}}>
            Add Your API Keys
          </div>
          <div style={{fontSize:13,color:C.muted,lineHeight:1.6,marginBottom:16}}>
            Your personal keys are used for enrichment instead of the platform's shared quota.
            Without them you get <strong style={{color:C.accentText}}>10 free checks/day</strong> per service.
            Keys are encrypted and only accessible by your account.
          </div>

          {/* Quota banner if running low */}
          {anyQuotaLow&&(
            <div style={{padding:"10px 14px",background:C.amber+"15",border:`1px solid ${C.amber}40`,
              borderRadius:8,fontSize:12,color:C.amber,marginBottom:16}}>
              ⚠ You're running low on free daily checks. Add your API keys to continue without limits.
            </div>
          )}
        </div>

        {/* Service list */}
        <div style={{padding:"0 24px"}}>
          {SERVICES.map(svc=>{
            const alreadySaved = existingKeys[svc.id] || saved[svc.id];
            return(
            <div key={svc.id} style={{marginBottom:16,padding:14,background:C.surfaceHi,
              border:`1px solid ${alreadySaved?C.green:C.border}`,borderRadius:10}}>
              <div style={{display:"flex",justifyContent:"space-between",
                alignItems:"flex-start",marginBottom:alreadySaved?0:8}}>
                <div>
                  <div style={{display:"flex",alignItems:"center",gap:8}}>
                    <span style={{fontSize:13,fontWeight:700,color:C.white||C.textHi}}>{svc.name}</span>
                    {alreadySaved
                      ? <span style={{fontSize:11,color:C.green,fontWeight:700}}>✓ Already saved</span>
                      : quota&&quota[svc.id]&&!quota[svc.id].unlimited&&(
                          <span style={{fontSize:11,padding:"1px 6px",borderRadius:3,
                            background:quota[svc.id].quota_remaining<=3?C.red+"20":C.accentDim,
                            color:quota[svc.id].quota_remaining<=3?C.red:C.accentText,fontWeight:600}}>
                            {quota[svc.id].quota_remaining}/{quota[svc.id].quota_total} free today
                          </span>
                        )
                    }
                  </div>
                  <div style={{fontSize:11,color:C.muted,marginTop:2}}>{svc.desc}</div>
                </div>
                {!alreadySaved&&(
                  <a href={svc.url} target="_blank" rel="noreferrer"
                    style={{fontSize:11,color:C.accentText,fontWeight:600,whiteSpace:"nowrap",marginLeft:8}}>
                    Get key →
                  </a>
                )}
              </div>
              {!alreadySaved&&(
                <div style={{display:"flex",gap:8,marginTop:8}}>
                  <input value={keys[svc.id]||""} onChange={e=>setKeys(p=>({...p,[svc.id]:e.target.value}))}
                    onKeyDown={e=>{if(e.key==="Enter")saveKey(svc.id);}}
                    placeholder={svc.placeholder}
                    style={{flex:1,background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                      color:C.inputText,padding:"8px 12px",borderRadius:7,fontSize:12,
                      outline:"none",fontFamily:"monospace"}}/>
                  <button onClick={()=>saveKey(svc.id)}
                    disabled={saving[svc.id]||!keys[svc.id]?.trim()}
                    style={{padding:"8px 14px",background:C.accent,border:"none",color:"#fff",
                      borderRadius:7,cursor:"pointer",fontSize:12,fontFamily:"inherit",
                      fontWeight:600,opacity:saving[svc.id]||!keys[svc.id]?.trim()?0.4:1}}>
                    {saving[svc.id]?"Saving...":"Save"}
                  </button>
                </div>
              )}
            </div>
            );
          })}
        </div>

        {/* Footer */}
        <div style={{padding:"16px 24px",borderTop:`1px solid ${C.border}`,
          display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <div style={{fontSize:11,color:C.muted}}>
            🔒 Keys are encrypted at rest. You can update them anytime in Settings.
          </div>
          <button onClick={onClose}
            style={{padding:"8px 20px",background:C.accentDim,border:`1px solid ${C.accent}40`,
              color:C.accentText,borderRadius:8,cursor:"pointer",fontSize:13,
              fontFamily:"inherit",fontWeight:600}}>
            {Object.keys(saved).length>0||Object.keys(existingKeys).length>0?"Done":"Skip for now"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── API KEYS SECTION IN SETTINGS ──────────────────────────────────────────────
const STATIC_SERVICES=[
  {service:"virustotal", name:"VirusTotal",    url:"https://www.virustotal.com/gui/my-apikey",          placeholder:"Enter your VT API key",    desc:"IOC enrichment — malware & IP reputation"},
  {service:"abuseipdb",  name:"AbuseIPDB",     url:"https://www.abuseipdb.com/account/api",             placeholder:"Enter your AbuseIPDB key",  desc:"IP abuse confidence scoring"},
  {service:"groq",       name:"Groq",          url:"https://console.groq.com/keys",                     placeholder:"gsk_xxxxxxxxxxxx",           desc:"SPL/KQL query generation (free)"},
  {service:"shodan",     name:"Shodan",        url:"https://account.shodan.io/",                        placeholder:"Enter your Shodan key",     desc:"Port scan & OSINT host lookup"},
  {service:"hibp",       name:"HaveIBeenPwned",url:"https://haveibeenpwned.com/API/Key",                placeholder:"Enter your HIBP key",       desc:"Email breach lookup in OSINT"},
  {service:"nvd",        name:"NVD",           url:"https://nvd.nist.gov/developers/request-an-api-key",placeholder:"Enter your NVD key",        desc:"CVE monitoring (higher rate limit)"},
];

function ApiKeysSection({token,C}){
  const [keyData,setKeyData]=useState(null); // null = loading, [] = failed/empty
  const [editing,setEditing]=useState({});
  const [saving,setSaving]=useState({});
  const [msg,setMsg]=useState({});
  const [err,setErr]=useState({});

  const load=()=>{
    api("/users/me/api-keys",{},token)
      .then(r=>r.ok?r.json():null)
      .then(d=>setKeyData(Array.isArray(d)?d:null))
      .catch(()=>setKeyData(null));
  };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(()=>{load();},[token]);

  async function saveKey(svc){
    const k=(editing[svc]||"").trim();
    if(!k)return;
    setSaving(p=>({...p,[svc]:true}));
    setErr(p=>({...p,[svc]:""}));
    try{
      const r=await api(`/users/me/api-keys/${svc}`,{method:"POST",body:JSON.stringify({api_key:k})},token);
      if(r.ok){
        setMsg(p=>({...p,[svc]:"✓ Saved"}));
        setEditing(p=>({...p,[svc]:""}));
        load();
      }else{
        const e=await r.json();
        setErr(p=>({...p,[svc]:e.detail||"Failed to save"}));
      }
    }catch{
      setErr(p=>({...p,[svc]:"Cannot reach server — deploy the backend first"}));
    }
    setSaving(p=>({...p,[svc]:false}));
    setTimeout(()=>setMsg(p=>({...p,[svc]:""})),3000);
  }

  async function removeKey(svc){
    try{
      await api(`/users/me/api-keys/${svc}`,{method:"DELETE"},token);
      setMsg(p=>({...p,[svc]:"✓ Removed"}));
      load();
      setTimeout(()=>setMsg(p=>({...p,[svc]:""})),3000);
    }catch{
      setErr(p=>({...p,[svc]:"Cannot reach server"}));
    }
  }

  // Merge static list with live data from backend
  const services = STATIC_SERVICES.map(s=>{
    const live = keyData?.find(k=>k.service===s.service);
    return {...s, ...live};
  });

  const backendDown = keyData === null;

  return(
    <div style={{marginBottom:28}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
        <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:1.5,textTransform:"uppercase"}}>
          My API Keys
        </div>
        {backendDown&&(
          <span style={{fontSize:11,color:C.amber,fontWeight:600}}>
            ⚠ Backend offline — keys shown below won't save until server is running
          </span>
        )}
      </div>
      <div style={{fontSize:12,color:C.muted,marginBottom:14,lineHeight:1.6}}>
        Add your personal API keys to remove the {DAILY_FREE_QUOTA} free checks/day limit.
        Keys are encrypted at rest and only used for your account's queries.
      </div>

      {services.map(k=>(
        <div key={k.service} style={{background:C.surface,
          border:`1px solid ${k.has_key?C.green+"50":C.border}`,
          borderRadius:10,padding:"14px 16px",marginBottom:10,boxShadow:C.shadow}}>

          {/* Header row */}
          <div style={{display:"flex",justifyContent:"space-between",
            alignItems:"flex-start",marginBottom:10,flexWrap:"wrap",gap:8}}>
            <div>
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:3}}>
                <span style={{fontSize:13,fontWeight:700,color:C.white}}>{k.name}</span>
                {k.has_key
                  ? <span style={{fontSize:11,color:C.green,fontWeight:700}}>✓ Personal key active</span>
                  : <span style={{fontSize:11,padding:"1px 7px",borderRadius:3,
                      background:C.accentDim,color:C.accentText,fontWeight:600}}>
                      {k.unlimited?"Unlimited":
                       k.quota_remaining!=null?`${k.quota_remaining}/${k.quota_total} free today`:
                       `${DAILY_FREE_QUOTA} free/day`}
                    </span>
                }
              </div>
              <div style={{fontSize:11,color:C.muted}}>{k.desc}</div>
              {k.has_key&&k.masked&&(
                <div style={{fontSize:10,color:C.muted,fontFamily:"monospace",marginTop:3}}>{k.masked}</div>
              )}
              {k.updated_at&&(
                <div style={{fontSize:10,color:C.muted}}>Updated: {new Date(k.updated_at).toLocaleDateString()}</div>
              )}
            </div>
            <div style={{display:"flex",gap:8,alignItems:"center"}}>
              <a href={k.url} target="_blank" rel="noreferrer"
                style={{fontSize:11,color:C.accentText,fontWeight:600,whiteSpace:"nowrap"}}>
                Get free key →
              </a>
              {k.has_key&&(
                <button onClick={()=>removeKey(k.service)}
                  style={{fontSize:11,padding:"3px 10px",background:"none",
                    border:`1px solid ${C.red}40`,color:C.red,borderRadius:5,
                    cursor:"pointer",fontFamily:"inherit"}}>
                  Remove
                </button>
              )}
            </div>
          </div>

          {/* Input row */}
          <div style={{display:"flex",gap:8}}>
            <input
              value={editing[k.service]||""}
              onChange={e=>setEditing(p=>({...p,[k.service]:e.target.value}))}
              onKeyDown={e=>{if(e.key==="Enter")saveKey(k.service);}}
              placeholder={k.has_key?"Paste new key to replace...":k.placeholder}
              style={{flex:1,background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                color:C.inputText,padding:"8px 12px",borderRadius:7,fontSize:12,
                outline:"none",fontFamily:"monospace"}}/>
            <button onClick={()=>saveKey(k.service)}
              disabled={saving[k.service]||!editing[k.service]?.trim()}
              style={{padding:"8px 16px",background:C.accent,border:"none",color:"#fff",
                borderRadius:7,cursor:"pointer",fontSize:12,fontFamily:"inherit",
                fontWeight:600,opacity:saving[k.service]||!editing[k.service]?.trim()?0.4:1}}>
              {saving[k.service]?"Saving...":(k.has_key?"Update":"Save")}
            </button>
          </div>

          {/* Feedback */}
          {msg[k.service]&&(
            <div style={{fontSize:12,color:C.green,marginTop:6,fontWeight:600}}>
              {msg[k.service]}
            </div>
          )}
          {err[k.service]&&(
            <div style={{fontSize:12,color:C.red,marginTop:6}}>{err[k.service]}</div>
          )}
        </div>
      ))}
    </div>
  );
}

const DAILY_FREE_QUOTA = 10;

function SettingsPage({themeName,setThemeName,token,onLogout,C,me,onOpenApiKeys}){
  const [showPw,setShowPw]=useState(false); const [cur,setCur]=useState(""); const [next,setNext]=useState("");
  const [pwMsg,setPwMsg]=useState(""); const [pwErr,setPwErr]=useState("");
  const [auditLog,setAuditLog]=useState([]); const [auditLoaded,setAuditLoaded]=useState(false);
  async function changePw(){const r=await api("/auth/change-password",{method:"POST",body:JSON.stringify({current_password:cur,new_password:next})},token);if(r.ok){setPwMsg("Password changed.");setCur("");setNext("");}else{const e=await r.json();setPwErr(e.detail||"Failed.");}}
  return(
    <div style={{maxWidth:700}}>
      <div style={{marginBottom:28}}>
        <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:1.5,textTransform:"uppercase",marginBottom:14}}>Theme</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12}}>
          {Object.entries(THEMES).map(([key,theme])=>(
            <button key={key} onClick={()=>{setThemeName(key);localStorage.setItem("tf_theme",key);}}
              style={{padding:"16px 14px",borderRadius:12,cursor:"pointer",textAlign:"center",
                transition:"all .2s",background:theme.bg,
                border:`2px solid ${themeName===key?theme.accent:theme.border}`}}>
              {/* Color dots */}
              <div style={{display:"flex",gap:5,justifyContent:"center",marginBottom:10}}>
                {[theme.accent,theme.green,theme.red,theme.purple].map((col,i)=>(
                  <div key={i} style={{width:10,height:10,borderRadius:"50%",background:col}}/>
                ))}
              </div>
              <div style={{fontSize:12,fontWeight:700,
                color:theme.white||theme.textHi||"#f1f5f9"}}>{theme.name}</div>
              <div style={{fontSize:10,color:theme.muted,marginTop:2}}>
                {key==="light"?"Professional light":key==="dark"?"Professional dark":"Terminal"}
              </div>
              {themeName===key&&(
                <div style={{fontSize:10,color:theme.accent,marginTop:4,fontWeight:700}}>
                  ✓ ACTIVE
                </div>
              )}
            </button>
          ))}
        </div>
      </div>
      <div style={{marginBottom:28}}>
        <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:1.5,textTransform:"uppercase",marginBottom:14}}>Account</div>
        <Card C={C}>
          <div style={{marginBottom:14}}><div style={{fontSize:12,color:C.muted,fontWeight:600}}>Signed in as</div><div style={{fontSize:15,color:C.white,fontWeight:700}}>{me?.username} <span style={{fontSize:12,color:C.muted,fontWeight:400}}>({me?.role})</span></div></div>
          <div style={{display:"flex",gap:8,marginBottom:showPw?16:0,flexWrap:"wrap"}}>
            <Btn onClick={()=>setShowPw(p=>!p)} variant="dim" C={C}>{showPw?"Cancel":"Change Password"}</Btn>
            <Btn onClick={onOpenApiKeys} variant="dim" C={C}>🔑 API Keys Setup</Btn>
            <Btn onClick={onLogout} variant="danger" C={C}>Sign Out</Btn>
          </div>
          {showPw&&(
            <div style={{borderTop:`1px solid ${C.border}`,paddingTop:16,marginTop:4}}>
              <Field label="Current Password" C={C}><Inp value={cur} onChange={setCur} type="password" C={C}/></Field>
              <Field label="New Password" C={C}><Inp value={next} onChange={setNext} type="password" C={C}/></Field>
              {pwErr&&<div style={{color:C.red,fontSize:12,marginBottom:10}}>{pwErr}</div>}
              {pwMsg&&<div style={{color:C.green,fontSize:12,marginBottom:10}}>{pwMsg}</div>}
              <Btn onClick={changePw} disabled={!cur||!next} C={C}>Save Password</Btn>
            </div>
          )}
        </Card>
      </div>
      <ApiKeysSection token={token} C={C}/>
      <div style={{marginBottom:28}}>
        <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:1.5,textTransform:"uppercase",marginBottom:14}}>Platform</div>
        <Card C={C}><div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,fontSize:13}}>{[["API","YOUR_DOMAIN"],["Enrichment Cache","24 hours"],["Token Expiry","8 hours"],["STIX","2.1"],["CVE Poll","Every 6 hours"]].map(([k,v])=><div key={k}><span style={{color:C.muted,fontWeight:600}}>{k}: </span><span style={{color:C.text}}>{v}</span></div>)}</div></Card>
      </div>
      {me?.role==="admin"&&(
        <div>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
            <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:1.5,textTransform:"uppercase"}}>Audit Log</div>
            <Btn onClick={()=>{api("/audit",{},token).then(r=>r.ok?r.json():[]).then(d=>{setAuditLog(d);setAuditLoaded(true);});}} variant="ghost" C={C} sm>Load</Btn>
          </div>
          {auditLoaded&&(
            <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,overflow:"hidden",boxShadow:C.shadow}}>
              <div style={{overflowX:"auto",maxHeight:400,overflowY:"auto"}}>
                <table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}>
                  <thead style={{position:"sticky",top:0}}><tr style={{background:C.surfaceHi,borderBottom:`1px solid ${C.border}`}}>{["Time","User","Action","Type","Indicator"].map(h=><th key={h} style={{padding:"10px 14px",textAlign:"left",color:C.muted,fontSize:11,fontWeight:700,whiteSpace:"nowrap"}}>{h}</th>)}</tr></thead>
                  <tbody>
                    {auditLog.length===0&&<tr><td colSpan={5} style={{padding:32,textAlign:"center",color:C.muted}}>No audit entries yet</td></tr>}
                    {auditLog.map((entry,idx)=>(
                      <tr key={entry.id} style={{borderBottom:`1px solid ${C.border}20`,background:idx%2===0?"transparent":C.surfaceHi+"40"}}>
                        <td style={{padding:"8px 14px",fontSize:11,color:C.muted,whiteSpace:"nowrap"}}>{new Date(entry.created_at).toLocaleString()}</td>
                        <td style={{padding:"8px 14px",color:C.accentText,fontWeight:600}}>{entry.username}</td>
                        <td style={{padding:"8px 14px"}}><span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,background:entry.action==="ADD"?C.green+"20":C.red+"20",color:entry.action==="ADD"?C.green:C.red}}>{entry.action}</span></td>
                        <td style={{padding:"8px 14px"}}><span style={{fontSize:11,padding:"2px 6px",borderRadius:3,background:C.badge,color:C.accentText}}>{entry.ioc_type}</span></td>
                        <td style={{padding:"8px 14px",fontSize:12,color:C.text,maxWidth:240,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{entry.ioc_value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── MAIN APP ──────────────────────────────────────────────────────────────────
export default function App(){
  const [themeName,setThemeName]=useState(()=>localStorage.getItem("tf_theme")||"light");
  const C=THEMES[themeName]||THEMES.operator;
  const [mode,setMode]=useState(()=>localStorage.getItem("tf_mode")||"ioc");
  function switchMode(m){setMode(m);localStorage.setItem("tf_mode",m);setView("dashboard");}
  const [showApiKeyModal,setShowApiKeyModal]=useState(false);
  const [cvelookupId,setCvelookupId]=useState("");
  const [session,setSession]=useState(()=>{const t=localStorage.getItem("tf_token");return t?{token:t}:null;});
  const [me,setMe]=useState(null);
  const [iocs,setIocs]=useState([]); const [campaigns,setCampaigns]=useState([]);
  const [users,setUsers]=useState([]); const [invites,setInvites]=useState([]);
  const [loading,setLoading]=useState(false); const [view,setView]=useState("dashboard");
  const [selectedIOC,setSelectedIOC]=useState(null);
  const [filterIndustry,setFilterIndustry]=useState("All"); const [filterType,setFilterType]=useState("All");
  const [filterTLP,setFilterTLP]=useState("All"); const [filterCampaign,setFilterCampaign]=useState("All");
  const [filterExpired,setFilterExpired]=useState(false); const [filterFP,setFilterFP]=useState(false);
  const [search,setSearch]=useState("");
  const blank={type:"IPv4",value:"",industry:"Fintech",tlp:"AMBER",confidence:75,description:"",tags:"",valid_days:90,mitre_techniques:[],campaign_id:""};
  const [form,setForm]=useState(blank);
  const [enriching,setEnriching]=useState(false); const [enrichErr,setEnrichErr]=useState("");
  const [saving,setSaving]=useState(false); const [saveErr,setSaveErr]=useState("");
  const [addResult,setAddResult]=useState(null); const [dupWarning,setDupWarning]=useState(null);
  const [newUser,setNewUser]=useState({username:"",password:"",role:"analyst"});
  const [userMsg,setUserMsg]=useState(""); const [userErr,setUserErr]=useState("");
  const [newInviteRole,setNewInviteRole]=useState("analyst"); const [inviteMsg,setInviteMsg]=useState("");
  const [newCampaign,setNewCampaign]=useState({name:"",description:"",threat_actor:""});
  const [campaignMsg,setCampaignMsg]=useState("");
  const [importTab,setImportTab]=useState("stix");
  const [stixText,setStixText]=useState(""); const [taxiiUrl,setTaxiiUrl]=useState("");
  const [taxiiCollection,setTaxiiCollection]=useState(""); const [taxiiToken,setTaxiiToken]=useState("");
  const [mispUrl,setMispUrl]=useState(""); const [mispKey,setMispKey]=useState("");
  const [csvFile,setCsvFile]=useState(null);
  const [importResult,setImportResult]=useState(null); const [importing,setImporting]=useState(false);
  // auth state — must be top-level
  const [authTab,setAuthTab]=useState("login");
  const [authUsername,setAuthUsername]=useState(""); const [authPassword,setAuthPassword]=useState("");
  const [authInviteCode,setAuthInviteCode]=useState(""); const [authErr,setAuthErr]=useState(""); const [authLoading,setAuthLoading]=useState(false);

  const token=session?.token;

  useEffect(()=>{
    if(!token)return;
    api("/auth/me",{},token).then(r=>r.ok?r.json():null).then(d=>{
      if(d){
        setMe(d);
        // Only show API key modal if:
        // 1. User hasn't dismissed it before (localStorage check)
        // 2. We confirm no keys are saved
        const dismissed = localStorage.getItem(`apikeys_setup_done_${d.id}`);
        if(dismissed) return; // user already set up or dismissed — never show again
        api("/users/me/api-keys",{},token)
          .then(r=>{ if(!r.ok) return; return r.json(); })
          .then(keys=>{
            if(!keys) return;
            const hasAny = Array.isArray(keys) && keys.some(k=>k.has_key);
            if(hasAny){
              // Keys exist — mark as done so we never check again
              localStorage.setItem(`apikeys_setup_done_${d.id}`,"1");
            } else {
              setShowApiKeyModal(true);
            }
          })
          .catch(()=>{});
      }
    });
  },[token]);

  const fetchIOCs=useCallback(async()=>{
    if(!token)return;setLoading(true);
    const p=new URLSearchParams();if(filterExpired)p.set("include_expired","true");if(filterFP)p.set("include_fp","true");
    const r=await api(`/iocs?${p}`,{},token);if(r.ok)setIocs(await r.json());setLoading(false);
  },[token,filterExpired,filterFP]);

  const fetchCampaigns=useCallback(async()=>{if(!token)return;const r=await api("/campaigns",{},token);if(r.ok)setCampaigns(await r.json());},[token]);
  useEffect(()=>{fetchIOCs();},[fetchIOCs]);
  useEffect(()=>{fetchCampaigns();},[fetchCampaigns]);
  useEffect(()=>{
    if(view==="users")api("/users",{},token).then(r=>r.ok?r.json():[]).then(setUsers);
    if(view==="invites")api("/invites",{},token).then(r=>r.ok?r.json():[]).then(setInvites);
  },[view,token]);

  function logout(){localStorage.removeItem("tf_token");setSession(null);setMe(null);}

  async function authLogin(){setAuthLoading(true);setAuthErr("");try{const r=await apiForm("/auth/login",{username:authUsername,password:authPassword});if(r.ok){const d=await r.json();localStorage.setItem("tf_token",d.access_token);setSession({token:d.access_token});setMe({username:d.username,role:d.role});}else{const e=await r.json();setAuthErr(e.detail||"Login failed");}}catch{setAuthErr("Cannot reach server.");}setAuthLoading(false);}
  async function authSignup(){setAuthLoading(true);setAuthErr("");try{const r=await api("/auth/signup",{method:"POST",body:JSON.stringify({username:authUsername,password:authPassword,invite_code:authInviteCode})});if(r.ok){const d=await r.json();localStorage.setItem("tf_token",d.access_token);setSession({token:d.access_token});setMe({username:d.username,role:d.role});}else{const e=await r.json();setAuthErr(e.detail||"Signup failed");}}catch{setAuthErr("Cannot reach server.");}setAuthLoading(false);}

  async function addIOC(){
    if(!form.value.trim())return;setSaving(true);setSaveErr("");setAddResult(null);
    const r=await api("/iocs",{method:"POST",body:JSON.stringify({...form,tags:form.tags.split(",").map(t=>t.trim()).filter(Boolean),confidence:parseInt(form.confidence)||75,valid_days:parseInt(form.valid_days)||90,campaign_id:form.campaign_id||null})},token);
    if(r.ok){const d=await r.json();setAddResult(d);setForm(blank);setDupWarning(null);await fetchIOCs();}
    else{const e=await r.json();setSaveErr(e.detail||"Failed.");}setSaving(false);
  }
  async function deleteIOC(id,e){e.stopPropagation();await api(`/iocs/${encodeURIComponent(id)}`,{method:"DELETE"},token);setIocs(p=>p.filter(i=>i.id!==id));}
  async function checkDup(val){if(!val.trim())return;const r=await api("/iocs/check",{method:"POST",body:JSON.stringify({value:val})},token);if(r.ok){const d=await r.json();setDupWarning(d.exists?d.existing:null);}}
  async function aiEnrich(){
    if(!form.value)return;setEnriching(true);setEnrichErr("");
    const r=await api("/ai/pre-fill",{method:"POST",body:JSON.stringify({ioc_type:form.type,value:form.value,industry:form.industry})},token);
    if(r.ok){const d=await r.json();setForm(p=>({...p,description:d.description??p.description,tags:Array.isArray(d.tags)?d.tags.join(", "):p.tags,confidence:d.confidence??p.confidence,tlp:TLP_LEVELS.includes(d.tlp)?d.tlp:p.tlp,mitre_techniques:Array.isArray(d.mitre_techniques)?d.mitre_techniques:p.mitre_techniques}));}
    else setEnrichErr("Pre-fill failed.");setEnriching(false);
  }
  async function downloadSTIX(){const r=await api("/stix/bundle",{},token);const bundle=await r.json();const blob=new Blob([JSON.stringify(bundle,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`stix-bundle-${Date.now()}.json`;a.click();URL.revokeObjectURL(url);}
  async function doImport(){
    setImporting(true);setImportResult(null);
    try{let r;
      if(importTab==="stix"){const bundle=JSON.parse(stixText);r=await api("/iocs/import/stix",{method:"POST",body:JSON.stringify({bundle})},token);}
      else if(importTab==="taxii"){r=await api("/iocs/import/taxii",{method:"POST",body:JSON.stringify({server_url:taxiiUrl,collection_id:taxiiCollection,token:taxiiToken||null})},token);}
      else if(importTab==="misp"){r=await api("/iocs/import/misp",{method:"POST",body:JSON.stringify({misp_url:mispUrl,misp_key:mispKey})},token);}
      else if(importTab==="csv"&&csvFile){const fd=new FormData();fd.append("file",csvFile);r=await fetch(`${API_BASE}/iocs/import/csv`,{method:"POST",headers:{Authorization:`Bearer ${token}`},body:fd});}
      if(r?.ok){setImportResult(await r.json());await fetchIOCs();}else if(r){const e=await r.json();setImportResult({error:e.detail});}
    }catch(e){setImportResult({error:String(e)});}setImporting(false);
  }

  const filtered=iocs.filter(i=>{
    if(filterIndustry!=="All"&&i.industry!==filterIndustry)return false;
    if(filterType!=="All"&&i.type!==filterType)return false;
    if(filterTLP!=="All"&&i.tlp!==filterTLP)return false;
    if(filterCampaign!=="All"&&i.campaign_id!==filterCampaign)return false;
    if(!filterFP&&i.false_positive)return false;
    if(search){const q=search.toLowerCase();return(i.value_defanged||i.value)?.toLowerCase().includes(q)||i.description?.toLowerCase().includes(q)||(i.tags||[]).some(t=>t.toLowerCase().includes(q));}
    return true;
  });

  const NAV=[
    ...(mode==="ioc"?IOC_NAV:CVE_NAV),
    ...(me?.role==="admin"?ADMIN_NAV:USER_NAV),
  ];

  if(!session){
    return(
      <div style={{display:"flex",alignItems:"center",justifyContent:"center",minHeight:"100vh",background:C.bg,padding:16,fontFamily:C.font||"inherit"}}>
        <style>{`@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap');*{box-sizing:border-box;}input::placeholder{color:${C.muted};}select option{background:${C.surface};color:${C.text};}`}</style>
        <div style={{width:"100%",maxWidth:440}}>
          <div style={{textAlign:"center",marginBottom:32}}><div style={{fontSize:24,fontWeight:700,letterSpacing:2,color:C.accentText,marginBottom:4}}>TFII</div><div style={{fontSize:12,color:C.muted,letterSpacing:1}}>THREATFEED INTELLIGENCE</div></div>
          <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:16,padding:36,boxShadow:C.shadow}}>
            <div style={{display:"flex",marginBottom:24,background:C.surfaceHi,borderRadius:10,padding:3}}>
              {["login","signup"].map(t=><button key={t} onClick={()=>{setAuthTab(t);setAuthErr("");}} style={{flex:1,padding:"8px",borderRadius:8,border:"none",cursor:"pointer",fontSize:13,fontFamily:"inherit",fontWeight:600,background:authTab===t?C.accent:"transparent",color:authTab===t?"#fff":C.muted}}>{t==="login"?"Sign In":"Sign Up"}</button>)}
            </div>
            <Field label="Username" C={C}><Inp value={authUsername} onChange={setAuthUsername} placeholder="username" C={C}/></Field>
            <Field label="Password" C={C}><Inp value={authPassword} onChange={setAuthPassword} type="password" placeholder="••••••••" C={C}/></Field>
            {authTab==="signup"&&<Field label="Invite Code" C={C}><Inp value={authInviteCode} onChange={setAuthInviteCode} placeholder="Get this from admin" C={C}/></Field>}
            {authErr&&<div style={{fontSize:12,color:C.red,marginBottom:16,padding:"10px 14px",background:C.red+"15",borderRadius:8,border:`1px solid ${C.red}30`}}>{authErr}</div>}
            <Btn onClick={authTab==="login"?authLogin:authSignup} disabled={authLoading||!authUsername||!authPassword||(authTab==="signup"&&!authInviteCode)} C={C} full>{authLoading?"Please wait...":(authTab==="login"?"Sign In →":"Create Account →")}</Btn>
            <div style={{marginTop:16,fontSize:11,color:C.muted,textAlign:"center"}}>{API_BASE.replace("https://","")}</div>
          </div>
        </div>
      </div>
    );
  }

  return(
    <div style={{display:"flex",height:"100vh",background:C.bg,color:C.text,fontFamily:C.font||"inherit",overflow:"hidden"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Space+Mono:wght@400;700&display=swap');
        *{box-sizing:border-box;}
        ::-webkit-scrollbar{width:5px;height:5px;}
        ::-webkit-scrollbar-track{background:transparent;}
        ::-webkit-scrollbar-thumb{background:${C.border};border-radius:10px;}
        ::-webkit-scrollbar-thumb:hover{background:${C.borderHi||C.border};}
        select option{background:${C.surface};color:${C.text};}
        input::placeholder,textarea::placeholder{color:${C.muted};}
        textarea{resize:vertical;}
        button:disabled{opacity:.4;cursor:not-allowed!important;}
        a{text-decoration:none;}
        .nav-item{transition:background .12s,color .12s;}
        .nav-item:hover{background:${C.navActive}!important;color:${C.accentText}!important;}
        .nav-item:hover svg{stroke:${C.accentText}!important;}
        @media(max-width:768px){.sidebar{width:60px!important;}.sidebar-label{display:none!important;}}
      `}</style>

      {selectedIOC&&<EnrichmentPanel ioc={selectedIOC} token={token} onClose={()=>setSelectedIOC(null)} C={C} me={me}/>}
      {showApiKeyModal&&<ApiKeyModal token={token} C={C} onClose={()=>{
        setShowApiKeyModal(false);
        if(me?.id) localStorage.setItem(`apikeys_setup_done_${me.id}`,"1");
      }}/>}

      {/* ── Sidebar ── */}
      <div className="sidebar" style={{
        width:240,background:C.sidebarBg||C.surface,
        borderRight:`1px solid ${C.border}`,
        display:"flex",flexDirection:"column",flexShrink:0,
        boxShadow:themeName==="light"?"1px 0 0 #f1f5f9":"none",
      }}>
        {/* Logo */}
        <div style={{padding:"20px 20px 16px",borderBottom:`1px solid ${C.border}`}}>
          <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:14}}>
            <div style={{width:32,height:32,borderRadius:8,background:C.accent,
              display:"flex",alignItems:"center",justifyContent:"center"}}>
              <NavIcon name="shield" size={16} color="#fff"/>
            </div>
            <div>
              <div style={{fontSize:15,fontWeight:800,letterSpacing:"-0.02em",color:C.white||C.textHi}}>TFII</div>
              <div style={{fontSize:10,color:C.muted,fontWeight:500,letterSpacing:"0.04em"}}>THREAT INTEL</div>
            </div>
          </div>
          {/* Mode switcher */}
          <div style={{display:"flex",background:C.surfaceHi,borderRadius:8,padding:3,gap:2}}>
            {[["ioc","IOC"],["cve","CVE"]].map(([m,label])=>(
              <button key={m} onClick={()=>switchMode(m)} style={{
                flex:1,padding:"5px 8px",borderRadius:6,border:"none",cursor:"pointer",
                fontSize:12,fontFamily:"inherit",fontWeight:600,letterSpacing:"0.02em",
                background:mode===m?C.accent:"transparent",
                color:mode===m?"#fff":C.muted,transition:"all .15s",
              }}>
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* Nav */}
        <nav style={{padding:"10px 10px",flex:1,overflowY:"auto"}}>
          {NAV.map(n=>{
            const active=view===n.id;
            return(
              <button key={n.id} className="nav-item" onClick={()=>setView(n.id)}
                style={{
                  display:"flex",alignItems:"center",gap:10,width:"100%",
                  padding:"9px 12px",borderRadius:8,marginBottom:2,
                  border:"none",cursor:"pointer",textAlign:"left",
                  background:active?C.navActive:"transparent",
                  color:active?C.accentText:C.text,
                  fontFamily:"inherit",fontSize:13,fontWeight:active?600:400,
                }}>
                <NavIcon name={n.icon} size={16} color={active?C.accentText:C.muted}/>
                <span className="sidebar-label">{n.label}</span>
              </button>
            );
          })}
        </nav>

        {/* User footer */}
        <div style={{padding:"12px 14px",borderTop:`1px solid ${C.border}`}}>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <div style={{width:30,height:30,borderRadius:"50%",background:C.accentDim,
              display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
              <span style={{fontSize:12,fontWeight:700,color:C.accentText}}>
                {(me?.username||"?")[0].toUpperCase()}
              </span>
            </div>
            <div className="sidebar-label" style={{flex:1,minWidth:0}}>
              <div style={{fontSize:12,fontWeight:600,color:C.white||C.textHi,
                overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{me?.username}</div>
              <div style={{fontSize:10,color:C.muted,textTransform:"capitalize"}}>{me?.role}</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Main area ── */}
      <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
        {/* Topbar */}
        <div style={{
          padding:"0 24px",height:58,
          borderBottom:`1px solid ${C.border}`,
          background:C.topbarBg||C.surface,
          display:"flex",alignItems:"center",
          justifyContent:"space-between",gap:16,flexShrink:0,
        }}>
          <div style={{fontSize:15,fontWeight:700,color:C.white||C.textHi,letterSpacing:"-0.01em"}}>
            {NAV.find(n=>n.id===view)?.label||view}
          </div>
          <GlobalSearch token={token} C={C} onSelect={setSelectedIOC} onCVELookup={(id)=>{setCvelookupId(id);setView("cvelookup");}}/>
          <div style={{display:"flex",gap:8,alignItems:"center",flexShrink:0}}>
            <NotificationBell token={token} C={C} isAdmin={me?.role==="admin"}/>
            {view==="feed"&&<>
              <button onClick={fetchIOCs} title="Refresh"
                style={{width:34,height:34,display:"flex",alignItems:"center",justifyContent:"center",
                  background:"none",border:`1px solid ${C.border}`,color:C.muted,
                  borderRadius:8,cursor:"pointer",fontSize:14}}>↻</button>
              <button onClick={downloadSTIX}
                style={{padding:"7px 14px",background:C.accentDim,border:`1px solid ${C.accent}30`,
                  color:C.accentText,borderRadius:8,cursor:"pointer",fontSize:12,
                  fontFamily:"inherit",fontWeight:600}}>STIX Export</button>
              <button onClick={()=>{setView("add");setAddResult(null);}}
                style={{padding:"7px 16px",background:C.accent,border:"none",color:"#fff",
                  borderRadius:8,cursor:"pointer",fontSize:13,fontFamily:"inherit",fontWeight:600,
                  display:"flex",alignItems:"center",gap:6}}>
                <NavIcon name="plus" size={14} color="#fff"/> Add IOC
              </button>
            </>}
          </div>
        </div>

        <div style={{flex:1,overflow:"auto",padding:"24px"}}>
          {view==="dashboard"&&<><Dashboard token={token} C={C}/><CVESummaryStrip token={token} C={C}/></>}
          {view==="cve"&&<CVEDashboard token={token} C={C}/>}
          {view==="cvelookup"&&<CVELookup token={token} C={C} initialId={cvelookupId}/>}
          {view==="cvewall"&&<CVEWall token={token} C={C}/>}
          {view==="map"&&<GeoMap token={token} C={C}/>}
          {view==="intel"&&<IntelNews token={token} C={C}/>}
          {view==="actors"&&<ThreatActors token={token} C={C}/>}
          {view==="osint"&&<OSINTTool token={token} C={C}/>}
          {view==="querygen"&&<QueryGenerator token={token} C={C}/>}
          {view==="public"&&<PublicSearch C={C}/>}
          {view==="settings"&&<SettingsPage themeName={themeName} setThemeName={setThemeName} token={token} onLogout={logout} C={C} me={me} onOpenApiKeys={()=>setShowApiKeyModal(true)}/>}

          {view==="feed"&&(
            <>
              {/* Filter bar */}
              <div style={{display:"flex",gap:8,marginBottom:16,flexWrap:"wrap",alignItems:"center"}}>
                <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search IOCs..."
                  style={{flex:1,minWidth:140,background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                    color:C.inputText,padding:"8px 12px",borderRadius:8,fontSize:13,
                    outline:"none",fontFamily:"inherit"}}/>
                {[[["All",...INDUSTRIES],filterIndustry,setFilterIndustry,"Industry"],
                  [["All",...IOC_TYPES],filterType,setFilterType,"Type"],
                  [["All",...TLP_LEVELS],filterTLP,setFilterTLP,"TLP"]].map(([opts,val,setVal,label],idx)=>(
                  <select key={idx} value={val} onChange={e=>setVal(e.target.value)}
                    style={{background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,
                      padding:"8px 10px",borderRadius:8,fontSize:12,outline:"none",fontFamily:"inherit"}}>
                    <option value="All">{label}: All</option>
                    {opts.slice(1).map(o=><option key={o}>{o}</option>)}
                  </select>
                ))}
                <select value={filterCampaign} onChange={e=>setFilterCampaign(e.target.value)}
                  style={{background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,
                    padding:"8px 10px",borderRadius:8,fontSize:12,outline:"none",fontFamily:"inherit"}}>
                  <option value="All">Campaign: All</option>
                  {campaigns.map(c=><option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
                <label style={{display:"flex",alignItems:"center",gap:5,fontSize:12,color:C.muted,cursor:"pointer"}}>
                  <input type="checkbox" checked={filterExpired} onChange={e=>setFilterExpired(e.target.checked)} style={{accentColor:C.accent}}/>Expired
                </label>
                <label style={{display:"flex",alignItems:"center",gap:5,fontSize:12,color:C.muted,cursor:"pointer"}}>
                  <input type="checkbox" checked={filterFP} onChange={e=>setFilterFP(e.target.checked)} style={{accentColor:C.accent}}/>FP
                </label>
              </div>

              {/* Count */}
              <div style={{fontSize:12,color:C.muted,marginBottom:12}}>
                <strong style={{color:C.white||C.textHi}}>{filtered.length}</strong> of {iocs.length} IOCs
              </div>

              {loading&&<div style={{textAlign:"center",padding:48,color:C.muted}}>Loading...</div>}

              {/* Compact card grid */}
              {!loading&&filtered.length===0&&(
                <div style={{textAlign:"center",padding:48,color:C.muted,background:C.surface,
                  border:`1px solid ${C.border}`,borderRadius:12}}>
                  {iocs.length===0?"No IOCs yet — add one above.":"No matches for current filters."}
                </div>
              )}
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(340px,1fr))",gap:10}}>
                {filtered.map(ioc=>{
                  const canDelete=me?.role==="admin"||ioc.created_by===me?.id;
                  const conf=ioc.confidence||0;
                  const confColor=conf>=75?C.green:conf>=50?C.amber:C.red;
                  return(
                    <div key={ioc.id} onClick={()=>setSelectedIOC(ioc)}
                      style={{background:C.surface,border:`1px solid ${
                        ioc.false_positive?C.amber+"50":ioc.expired?C.border:C.border}`,
                        borderRadius:10,padding:"12px 14px",cursor:"pointer",
                        boxShadow:C.shadow,transition:"border-color .12s, box-shadow .12s",
                        opacity:ioc.expired?0.65:1}}
                      onMouseEnter={e=>{e.currentTarget.style.borderColor=C.accent;e.currentTarget.style.boxShadow=C.shadowMd||C.shadow;}}
                      onMouseLeave={e=>{e.currentTarget.style.borderColor=ioc.false_positive?C.amber+"50":C.border;e.currentTarget.style.boxShadow=C.shadow;}}>

                      {/* Top row: type badge + value + delete */}
                      <div style={{display:"flex",alignItems:"flex-start",gap:8,marginBottom:8}}>
                        <span style={{fontSize:10,padding:"2px 7px",borderRadius:4,fontWeight:700,
                          background:C.accentDim,color:C.accentText,flexShrink:0,marginTop:2}}>
                          {ioc.type}
                        </span>
                        <span style={{fontWeight:600,color:C.white||C.textHi,
                          flex:1,wordBreak:"break-all",lineHeight:1.3,fontFamily:"monospace",fontSize:12}}>
                          {ioc.value_defanged||ioc.value}
                        </span>
                        {canDelete&&(
                          <button onClick={e=>deleteIOC(ioc.id,e)}
                            style={{background:"none",border:"none",color:C.muted,cursor:"pointer",
                              fontSize:16,padding:0,flexShrink:0,opacity:.5,lineHeight:1}}>×</button>
                        )}
                      </div>

                      {/* Mid row: TLP + industry + conf bar */}
                      <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8,flexWrap:"wrap"}}>
                        <TLPBadge level={ioc.tlp}/>
                        {ioc.industry&&<span style={{fontSize:11,color:C.purple,fontWeight:500}}>{ioc.industry}</span>}
                        {ioc.campaign_id&&<span style={{fontSize:11,color:C.amber,fontWeight:500}}>📁 Campaign</span>}
                        {ioc.false_positive&&<span style={{fontSize:10,color:C.amber,border:`1px solid ${C.amber}40`,padding:"1px 5px",borderRadius:3,fontWeight:700}}>FP</span>}
                        {ioc.expired&&<span style={{fontSize:10,color:C.red,border:`1px solid ${C.red}40`,padding:"1px 5px",borderRadius:3,fontWeight:700}}>EXPIRED</span>}
                        <div style={{marginLeft:"auto",display:"flex",alignItems:"center",gap:6}}>
                          <div style={{width:40,height:3,background:C.border,borderRadius:2,overflow:"hidden"}}>
                            <div style={{width:`${conf}%`,height:"100%",background:confColor,borderRadius:2}}/>
                          </div>
                          <span style={{fontSize:10,color:confColor,fontWeight:700}}>{conf}%</span>
                        </div>
                      </div>

                      {/* Bottom row: tags + MITRE + author */}
                      <div style={{display:"flex",alignItems:"center",gap:6,flexWrap:"wrap"}}>
                        {(ioc.tags||[]).slice(0,3).map(t=><Tag key={t} label={t} C={C}/>)}
                        {(ioc.tags||[]).length>3&&<Tag label={`+${ioc.tags.length-3}`} C={C}/>}
                        {(ioc.mitre_techniques||[]).length>0&&(
                          <span style={{fontSize:10,padding:"1px 6px",borderRadius:3,
                            background:C.purple+"20",color:C.purple,fontWeight:600}}>
                            {ioc.mitre_techniques[0].split(" - ")[0]}
                            {ioc.mitre_techniques.length>1&&` +${ioc.mitre_techniques.length-1}`}
                          </span>
                        )}
                        <span style={{marginLeft:"auto",fontSize:10,color:C.muted}}>{ioc.author||"?"}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
              {!loading&&filtered.length>0&&(
                <div style={{marginTop:12,fontSize:11,color:C.muted,textAlign:"center"}}>
                  Click any card for enrichment details, notes, score history, and relationships
                </div>
              )}
            </>
          )}

          {view==="add"&&(
            <div style={{maxWidth:620}}>
              {addResult&&(
                <div style={{marginBottom:20,padding:18,background:C.green+"10",border:`1px solid ${C.green}30`,borderRadius:12}}>
                  <div style={{fontSize:14,color:C.green,fontWeight:700,marginBottom:10}}>✓ IOC Submitted — Validation Complete</div>
                  <div style={{fontSize:13,color:C.text,marginBottom:4}}>Stored as: <code style={{color:C.accentText}}>{addResult.value_defanged||addResult.value_canonical}</code></div>
                  <div style={{fontSize:13,color:C.text,marginBottom:4}}>Confidence: <strong style={{color:C.green}}>{addResult.confidence}</strong></div>
                  {addResult.enrichment?.confidence_reasons?.map((r,i)=><div key={i} style={{fontSize:11,color:C.muted,marginTop:2}}>› {r}</div>)}
                  <button onClick={()=>setAddResult(null)} style={{marginTop:12,background:"none",border:`1px solid ${C.green}40`,color:C.green,padding:"6px 16px",borderRadius:6,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600}}>+ Add another</button>
                </div>
              )}
              {!addResult&&(<>
                <div style={{marginBottom:20,padding:14,background:C.accentDim,border:`1px solid ${C.accent}28`,borderRadius:10,fontSize:13,color:C.accentText,lineHeight:1.7}}>Fanged IOCs normalized automatically. Confidence validated via VT, AbuseIPDB, URLhaus. Results cached 24h.</div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
                  <Field label="IOC Type" C={C}><Sel value={form.type} onChange={v=>setForm(p=>({...p,type:v}))} options={IOC_TYPES} C={C}/></Field>
                  <Field label="Industry" C={C}><Sel value={form.industry} onChange={v=>setForm(p=>({...p,industry:v}))} options={INDUSTRIES} C={C}/></Field>
                </div>
                <Field label="Indicator Value" C={C}><Inp value={form.value} onChange={v=>{setForm(p=>({...p,value:v}));setDupWarning(null);}} placeholder="e.g. hxxp://evil[.]com or 185[.]220[.]101[.]45" C={C}/></Field>
                {dupWarning&&<div style={{marginBottom:14,padding:"10px 14px",background:C.amber+"10",border:`1px solid ${C.amber}40`,borderRadius:8,fontSize:13,color:C.amber}}>⚠ Already exists — added by <strong>{dupWarning.author||"unknown"}</strong> · conf {dupWarning.confidence}</div>}
                <div style={{display:"flex",gap:8,marginBottom:18,flexWrap:"wrap"}}>
                  <Btn onClick={aiEnrich} disabled={enriching||!form.value} variant="dim" C={C}>{enriching?"Pre-filling...":"⚡ Pre-fill"}</Btn>
                  <Btn onClick={()=>checkDup(form.value)} disabled={!form.value} variant="ghost" C={C}>Check Duplicate</Btn>
                  {enrichErr&&<span style={{fontSize:12,color:C.red,alignSelf:"center"}}>{enrichErr}</span>}
                </div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
                  <Field label="TLP Level" C={C}><Sel value={form.tlp} onChange={v=>setForm(p=>({...p,tlp:v}))} options={TLP_LEVELS} C={C}/></Field>
                  <Field label="Base Confidence" C={C}><Inp value={form.confidence} onChange={v=>setForm(p=>({...p,confidence:v}))} type="number" C={C}/></Field>
                </div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>
                  <Field label="Expiry (days)" C={C}><Inp value={form.valid_days} onChange={v=>setForm(p=>({...p,valid_days:v}))} type="number" placeholder="90" C={C}/></Field>
                  <Field label="Campaign" C={C}>
                    <select value={form.campaign_id} onChange={e=>setForm(p=>({...p,campaign_id:e.target.value}))} style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"10px 12px",borderRadius:8,fontSize:14,outline:"none",fontFamily:"inherit"}}>
                      <option value="">None</option>{campaigns.map(c=><option key={c.id} value={c.id}>{c.name}</option>)}
                    </select>
                  </Field>
                </div>
                <Field label="Description" C={C}><Inp value={form.description} onChange={v=>setForm(p=>({...p,description:v}))} placeholder="Threat context..." C={C} rows={3}/></Field>
                <Field label="Tags (comma-separated)" C={C}><Inp value={form.tags} onChange={v=>setForm(p=>({...p,tags:v}))} placeholder="c2, malware, apt" C={C}/></Field>
                <Field label="MITRE ATT&CK Techniques" C={C}>
                  <select onChange={e=>{if(e.target.value&&!form.mitre_techniques.includes(e.target.value)){setForm(p=>({...p,mitre_techniques:[...p.mitre_techniques,e.target.value]}));}e.target.value="";}}
                    style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"10px 12px",borderRadius:8,fontSize:14,outline:"none",fontFamily:"inherit",marginBottom:8}}>
                    <option value="">Add technique...</option>{MITRE_TECHNIQUES.map(t=><option key={t} value={t}>{t}</option>)}
                  </select>
                  <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                    {form.mitre_techniques.map(t=><span key={t} onClick={()=>setForm(p=>({...p,mitre_techniques:p.mitre_techniques.filter(x=>x!==t)}))} style={{fontSize:11,padding:"3px 8px",borderRadius:4,background:C.purple+"20",color:C.purple,fontFamily:"inherit",border:`1px solid ${C.purple}40`,cursor:"pointer",display:"flex",alignItems:"center",gap:4}}>{t.split(" - ")[0]} ×</span>)}
                  </div>
                </Field>
                {saveErr&&<div style={{fontSize:12,color:C.red,marginBottom:12,padding:"10px 14px",background:C.red+"10",borderRadius:8}}>{saveErr}</div>}
                <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
                  <Btn onClick={addIOC} disabled={!form.value.trim()||saving} C={C}>{saving?"Validating & saving...":"Submit IOC"}</Btn>
                  <Btn onClick={()=>setView("feed")} variant="ghost" C={C}>Cancel</Btn>
                </div>
              </>)}
            </div>
          )}

          {view==="campaigns"&&(
            <div style={{maxWidth:800}}>
              <Card C={C} style={{marginBottom:24}}>
                <div style={{fontSize:13,fontWeight:700,color:C.white,marginBottom:16}}>Create Campaign</div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                  <Field label="Name" C={C}><Inp value={newCampaign.name} onChange={v=>setNewCampaign(p=>({...p,name:v}))} placeholder="Operation Sandstorm" C={C}/></Field>
                  <Field label="Threat Actor" C={C}><Inp value={newCampaign.threat_actor} onChange={v=>setNewCampaign(p=>({...p,threat_actor:v}))} placeholder="APT34, Lazarus..." C={C}/></Field>
                </div>
                <Field label="Description" C={C}><Inp value={newCampaign.description} onChange={v=>setNewCampaign(p=>({...p,description:v}))} placeholder="Campaign overview..." C={C} rows={2}/></Field>
                {campaignMsg&&<div style={{fontSize:12,color:C.green,marginBottom:10}}>{campaignMsg}</div>}
                <Btn onClick={async()=>{const r=await api("/campaigns",{method:"POST",body:JSON.stringify(newCampaign)},token);if(r.ok){setCampaignMsg("Campaign created.");setNewCampaign({name:"",description:"",threat_actor:""});fetchCampaigns();}}} disabled={!newCampaign.name} C={C}>Create Campaign</Btn>
              </Card>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:1.5,textTransform:"uppercase",marginBottom:12}}>Active Campaigns ({campaigns.length})</div>
              {campaigns.map(c=>(
                <Card key={c.id} C={C} style={{marginBottom:12}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
                    <div><div style={{fontSize:14,color:C.white,fontWeight:700,marginBottom:4}}>{c.name}</div>{c.threat_actor&&<div style={{fontSize:12,color:C.red,marginBottom:4}}>Threat Actor: {c.threat_actor}</div>}{c.description&&<div style={{fontSize:12,color:C.muted,lineHeight:1.6}}>{c.description}</div>}</div>
                    <div style={{textAlign:"right",flexShrink:0,marginLeft:16}}><div style={{fontSize:22,fontWeight:700,color:C.accentText}}>{c.ioc_count}</div><div style={{fontSize:10,color:C.muted}}>IOCs</div></div>
                  </div>
                </Card>
              ))}
            </div>
          )}

          {view==="import"&&(
            <div style={{maxWidth:700}}>
              <div style={{display:"flex",marginBottom:20,background:C.surfaceHi,borderRadius:10,padding:3,gap:2,flexWrap:"wrap"}}>
                {["stix","taxii","misp","csv"].map(t=><button key={t} onClick={()=>{setImportTab(t);setImportResult(null);}} style={{padding:"7px 16px",borderRadius:8,border:"none",cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600,background:importTab===t?C.accent:"transparent",color:importTab===t?"#fff":C.muted}}>{t.toUpperCase()}</button>)}
              </div>
              {importTab==="stix"&&(<><div style={{fontSize:12,color:C.muted,marginBottom:14,lineHeight:1.7}}>Paste a STIX 2.1 bundle. Each indicator is parsed, normalized, enriched, and stored.</div><Field label="STIX Bundle JSON" C={C}><Inp value={stixText} onChange={setStixText} placeholder='{"type":"bundle","spec_version":"2.1","objects":[...]}' C={C} rows={10}/></Field><Btn onClick={doImport} disabled={!stixText.trim()||importing} C={C}>{importing?"Importing...":"Import Bundle"}</Btn></>)}
              {importTab==="taxii"&&(<><div style={{fontSize:12,color:C.muted,marginBottom:14,lineHeight:1.7}}>Poll a remote TAXII 2.1 server and import all indicators.</div><Field label="TAXII Server URL" C={C}><Inp value={taxiiUrl} onChange={setTaxiiUrl} placeholder="https://taxii.example.com" C={C}/></Field><Field label="Collection ID" C={C}><Inp value={taxiiCollection} onChange={setTaxiiCollection} placeholder="collection-uuid" C={C}/></Field><Field label="Bearer Token (optional)" C={C}><Inp value={taxiiToken} onChange={setTaxiiToken} type="password" C={C}/></Field><Btn onClick={doImport} disabled={!taxiiUrl||!taxiiCollection||importing} C={C}>{importing?"Polling...":"Poll TAXII Server"}</Btn></>)}
              {importTab==="misp"&&(<><div style={{fontSize:12,color:C.muted,marginBottom:14,lineHeight:1.7}}>Pull IOCs from a MISP instance via REST API.</div><Field label="MISP URL" C={C}><Inp value={mispUrl} onChange={setMispUrl} placeholder="https://your-misp.example.com" C={C}/></Field><Field label="MISP API Key" C={C}><Inp value={mispKey} onChange={setMispKey} type="password" C={C}/></Field><Btn onClick={doImport} disabled={!mispUrl||!mispKey||importing} C={C}>{importing?"Pulling...":"Pull from MISP"}</Btn></>)}
              {importTab==="csv"&&(<><div style={{fontSize:12,color:C.muted,marginBottom:14,lineHeight:1.7}}>Upload CSV with columns: <code style={{color:C.accentText}}>type, value, industry, tlp, confidence, description, tags, valid_days</code></div><Field label="CSV File" C={C}><input type="file" accept=".csv" onChange={e=>setCsvFile(e.target.files[0])} style={{color:C.inputText,fontFamily:"inherit",fontSize:13}}/></Field><Btn onClick={doImport} disabled={!csvFile||importing} C={C}>{importing?"Importing...":"Import CSV"}</Btn></>)}
              {importResult&&(
                <div style={{marginTop:20,padding:16,background:importResult.error?C.red+"10":C.green+"10",border:`1px solid ${importResult.error?C.red:C.green}30`,borderRadius:10}}>
                  {importResult.error?<div style={{color:C.red,fontSize:13}}>Error: {importResult.error}</div>:(<><div style={{color:C.green,fontSize:14,fontWeight:700,marginBottom:6}}>Import Complete</div><div style={{fontSize:13,color:C.text}}>Imported: <strong>{importResult.imported}</strong> · Skipped: {importResult.skipped}</div>{importResult.errors?.length>0&&<div style={{fontSize:12,color:C.amber,marginTop:6}}>{importResult.errors.length} errors</div>}</>)}
                </div>
              )}
            </div>
          )}

          {view==="export"&&(
            <div style={{maxWidth:700}}>
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:12,marginBottom:24}}>
                {[["Total IOCs",iocs.length],["STIX Spec","2.1"],["Pattern","stix"]].map(([l,v])=>(
                  <Card key={l} C={C}><div style={{fontSize:11,color:C.muted,marginBottom:6,fontWeight:600,letterSpacing:.5,textTransform:"uppercase"}}>{l}</div><div style={{fontSize:22,color:C.accentText,fontWeight:700}}>{v}</div></Card>
                ))}
              </div>
              <Btn onClick={downloadSTIX} C={C}>Download STIX Bundle ({iocs.length} IOCs)</Btn>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:1.5,textTransform:"uppercase",marginBottom:10,marginTop:24}}>TAXII Connector (OpenCTI)</div>
              {[["Server URL",`${API_BASE}/taxii/`],["Collection ID","a45ef559-3f21-4b78-9cde-ef0123456789"],["Auth","Authorization: Bearer <jwt-token>"],["Interval","3600 seconds"]].map(([l,v])=>(
                <Card key={l} C={C} style={{marginBottom:10,padding:"12px 16px"}}><div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4,textTransform:"uppercase",letterSpacing:.5}}>{l}</div><code style={{fontSize:12,color:C.accentText,fontFamily:"monospace",wordBreak:"break-all"}}>{v}</code></Card>
              ))}
            </div>
          )}

          {view==="users"&&me?.role==="admin"&&(
            <div style={{maxWidth:800}}>
              <Card C={C} style={{marginBottom:24}}>
                <div style={{fontSize:13,fontWeight:700,color:C.white,marginBottom:16}}>Create New User</div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(150px,1fr))",gap:12}}>
                  <Field label="Username" C={C}><Inp value={newUser.username} onChange={v=>setNewUser(p=>({...p,username:v}))} placeholder="analyst_name" C={C}/></Field>
                  <Field label="Password" C={C}><Inp value={newUser.password} onChange={v=>setNewUser(p=>({...p,password:v}))} type="password" placeholder="••••••••" C={C}/></Field>
                  <Field label="Role" C={C}><Sel value={newUser.role} onChange={v=>setNewUser(p=>({...p,role:v}))} options={["analyst","admin"]} C={C}/></Field>
                </div>
                {userErr&&<div style={{fontSize:12,color:C.red,marginBottom:10}}>{userErr}</div>}
                {userMsg&&<div style={{fontSize:12,color:C.green,marginBottom:10}}>{userMsg}</div>}
                <Btn onClick={async()=>{const r=await api("/users",{method:"POST",body:JSON.stringify(newUser)},token);if(r.ok){setUserMsg(`User ${newUser.username} created.`);setNewUser({username:"",password:"",role:"analyst"});api("/users",{},token).then(r=>r.ok?r.json():[]).then(setUsers);}else{const e=await r.json();setUserErr(e.detail||"Failed");}}} disabled={!newUser.username||!newUser.password} C={C}>Create User</Btn>
              </Card>
              <Card C={C} style={{overflow:"hidden",padding:0}}>
                <table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}>
                  <thead><tr style={{background:C.surfaceHi,borderBottom:`1px solid ${C.border}`}}>{["Username","Role","Status","Created",""].map(h=><th key={h} style={{padding:"10px 14px",textAlign:"left",color:C.muted,fontSize:11,fontWeight:700}}>{h}</th>)}</tr></thead>
                  <tbody>
                    {users.map((u,idx)=>(
                      <tr key={u.id} style={{borderBottom:`1px solid ${C.border}20`,background:idx%2===0?"transparent":C.surfaceHi+"40"}}>
                        <td style={{padding:"10px 14px",color:C.white,fontWeight:500}}>{u.username}{u.id===me?.id&&<span style={{color:C.muted,fontSize:11}}> (you)</span>}</td>
                        <td style={{padding:"10px 14px"}}><span style={{fontSize:11,padding:"2px 8px",borderRadius:4,background:u.role==="admin"?C.purple+"20":C.green+"20",color:u.role==="admin"?C.purple:C.green,fontWeight:600}}>{u.role}</span></td>
                        <td style={{padding:"10px 14px"}}><span style={{fontSize:12,color:u.active?C.green:C.red,fontWeight:500}}>{u.active?"Active":"Disabled"}</span></td>
                        <td style={{padding:"10px 14px",fontSize:12,color:C.muted}}>{new Date(u.created_at).toLocaleDateString()}</td>
                        <td style={{padding:"10px 14px"}}>{u.id!==me?.id&&<button onClick={async()=>{await api(`/users/${u.id}/${u.active?"disable":"enable"}`,{method:"PATCH"},token);api("/users",{},token).then(r=>r.ok?r.json():[]).then(setUsers);}} style={{padding:"3px 10px",background:"none",border:`1px solid ${u.active?C.red:C.accent}40`,color:u.active?C.red:C.accentText,borderRadius:4,cursor:"pointer",fontSize:11,fontFamily:"inherit",fontWeight:600}}>{u.active?"Disable":"Enable"}</button>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Card>
            </div>
          )}

          {view==="invites"&&me?.role==="admin"&&(
            <div style={{maxWidth:600}}>
              <Card C={C} style={{marginBottom:24}}>
                <div style={{fontSize:13,fontWeight:700,color:C.white,marginBottom:16}}>Generate Invite Code</div>
                <div style={{display:"flex",gap:12,alignItems:"flex-end",flexWrap:"wrap"}}>
                  <Field label="Role" C={C}><Sel value={newInviteRole} onChange={setNewInviteRole} options={["analyst","admin"]} C={C}/></Field>
                  <Btn onClick={async()=>{const r=await api("/invites",{method:"POST",body:JSON.stringify({role:newInviteRole})},token);if(r.ok){const d=await r.json();setInviteMsg(`Code: ${d.code} (${d.role})`);api("/invites",{},token).then(r=>r.ok?r.json():[]).then(setInvites);}}} C={C}>Generate</Btn>
                </div>
                {inviteMsg&&<div style={{marginTop:12,padding:"10px 14px",background:C.green+"10",border:`1px solid ${C.green}30`,borderRadius:8,fontSize:14,color:C.green,fontFamily:"monospace",fontWeight:700}}>{inviteMsg}</div>}
              </Card>
              <Card C={C} style={{overflow:"hidden",padding:0}}>
                <table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}>
                  <thead><tr style={{background:C.surfaceHi,borderBottom:`1px solid ${C.border}`}}>{["Code","Role","Status","Created"].map(h=><th key={h} style={{padding:"10px 14px",textAlign:"left",color:C.muted,fontSize:11,fontWeight:700}}>{h}</th>)}</tr></thead>
                  <tbody>
                    {invites.map((inv,idx)=>(
                      <tr key={inv.code} style={{borderBottom:`1px solid ${C.border}20`,background:idx%2===0?"transparent":C.surfaceHi+"40"}}>
                        <td style={{padding:"10px 14px",fontFamily:"monospace",fontSize:12,color:inv.used?C.muted:C.accentText,textDecoration:inv.used?"line-through":"none"}}>{inv.code}</td>
                        <td style={{padding:"10px 14px",fontSize:12,color:C.muted}}>{inv.role}</td>
                        <td style={{padding:"10px 14px"}}><span style={{fontSize:12,color:inv.used?C.muted:C.green,fontWeight:500}}>{inv.used?"Used":"Available"}</span></td>
                        <td style={{padding:"10px 14px",fontSize:12,color:C.muted}}>{new Date(inv.created_at).toLocaleDateString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Card>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
