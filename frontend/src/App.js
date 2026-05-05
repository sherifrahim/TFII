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
  operator:{name:"Operator",font:"'Space Mono',monospace",bg:"#07070e",surface:"#0d0d1c",surfaceHi:"#111126",border:"#1a1a30",accent:"#00e5c0",accentDim:"#00e5c014",accentText:"#00e5c0",text:"#c4c4e0",muted:"#484870",white:"#f0f0ff",green:"#00e676",amber:"#ffab00",red:"#ff5252",purple:"#a78bfa",inputBg:"#0a0a18",inputBorder:"#2a2a45",inputText:"#e0e0f8",shadow:"0 2px 12px #00000060",badge:"#141428"},
  nebula:{name:"Nebula",font:"'Inter',sans-serif",bg:"#08001a",surface:"#0f0025",surfaceHi:"#180038",border:"#2a0055",accent:"#c44dff",accentDim:"#c44dff12",accentText:"#d580ff",text:"#d8c8f0",muted:"#7055a0",white:"#f5eeff",green:"#00ffaa",amber:"#ffcc44",red:"#ff4488",purple:"#ff80ff",inputBg:"#0c001f",inputBorder:"#350070",inputText:"#ecdeff",shadow:"0 4px 32px #8800ff22",badge:"#150030",glow:"0 0 20px #c44dff30"},
  light:{name:"Light",font:"'Inter',sans-serif",bg:"#f4f6fb",surface:"#ffffff",surfaceHi:"#f0f3fa",border:"#e2e6f0",accent:"#2563eb",accentDim:"#2563eb12",accentText:"#2563eb",text:"#374151",muted:"#9ca3af",white:"#111827",green:"#16a34a",amber:"#d97706",red:"#dc2626",purple:"#7c3aed",inputBg:"#ffffff",inputBorder:"#d1d5db",inputText:"#111827",shadow:"0 2px 16px #0000001a",badge:"#f0f3fa"},
};

// ── MODE NAV DEFINITIONS ──────────────────────────────────────────────────────
const IOC_NAV=[
  {id:"dashboard",label:"Dashboard",    icon:"▦"},
  {id:"feed",     label:"IOC Feed",     icon:"◈"},
  {id:"add",      label:"Add IOC",      icon:"＋"},
  {id:"campaigns",label:"Campaigns",    icon:"◎"},
  {id:"map",      label:"Geo Map",      icon:"🗺"},
  {id:"public",   label:"Public Lookup",icon:"🌐"},
  {id:"import",   label:"Import",       icon:"↓"},
  {id:"export",   label:"Export",       icon:"↑"},
];
const CVE_NAV=[
  {id:"dashboard",label:"Dashboard",    icon:"▦"},
  {id:"cve",      label:"CVE Monitor",  icon:"🛡️"},
  {id:"intel",    label:"Intel Wall",   icon:"📡"},
  {id:"actors",   label:"Threat Actors",icon:"⚡"},
  {id:"osint",    label:"OSINT",        icon:"🔍"},
  {id:"querygen", label:"Query Builder",icon:"⌨"},
];
const ADMIN_NAV=[
  {id:"settings", label:"Settings",     icon:"⚙"},
  {id:"users",    label:"Users",        icon:"👥"},
  {id:"invites",  label:"Invites",      icon:"✉"},
];
const USER_NAV=[
  {id:"settings", label:"Settings",     icon:"⚙"},
];

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
function StatCard({label,value,color,C}){
  return(
    <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:"18px 20px",boxShadow:C.shadow}}>
      <div style={{fontSize:11,color:C.muted,marginBottom:8,fontWeight:600,letterSpacing:.5,textTransform:"uppercase"}}>{label}</div>
      <div style={{fontSize:32,fontWeight:700,color:color||C.accentText}}>{value}</div>
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
function CVEDetail({cve,token,onClose,C}){
  const [detail,setDetail]=useState(null);
  useEffect(()=>{
    api(`/cves/${encodeURIComponent(cve.cve_id)}`,{},token).then(r=>r.ok?r.json():null).then(d=>{if(d)setDetail(d);});
  },[cve.cve_id,token]);
  const d=detail||cve;
  return(
    <div style={{position:"fixed",inset:0,background:"#00000090",display:"flex",alignItems:"center",justifyContent:"center",zIndex:600,padding:16}} onClick={onClose}>
      <div onClick={e=>e.stopPropagation()} style={{width:"100%",maxWidth:720,maxHeight:"92vh",overflowY:"auto",background:C.surface,border:`1px solid ${C.border}`,borderRadius:16,boxShadow:C.shadow}}>
        <div style={{padding:"20px 24px",borderBottom:`1px solid ${C.border}`}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
            <div style={{flex:1,marginRight:12}}>
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8,flexWrap:"wrap"}}>
                <span style={{fontSize:14,fontWeight:700,color:C.accentText,fontFamily:"monospace"}}>{d.cve_id}</span>
                <SevBadge severity={d.cvss_severity} score={d.cvss_score} C={C}/>
                {d.kev_listed&&<span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,background:C.red+"20",color:C.red,border:`1px solid ${C.red}40`}}>🚨 CISA KEV</span>}
                <PatchBadge available={d.patch_available} url={d.patch_url} C={C}/>
              </div>
              <div style={{fontSize:13,color:C.muted}}>Asset: <strong style={{color:C.white}}>{d.asset_name}</strong></div>
            </div>
            <button onClick={onClose} style={{background:"none",border:"none",color:C.muted,fontSize:22,cursor:"pointer",padding:0}}>×</button>
          </div>
        </div>
        <div style={{padding:24}}>
          <div style={{background:C.surfaceHi,borderRadius:10,padding:16,marginBottom:16,fontSize:13,color:C.text,lineHeight:1.7}}>{d.description}</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:12,marginBottom:16}}>
            {[["CVSS Score",d.cvss_score?`${d.cvss_score}/10`:"N/A",(d.cvss_score||0)>=9?C.red:(d.cvss_score||0)>=7?C.amber:C.green],
              ["EPSS Score",d.epss_score?`${(d.epss_score*100).toFixed(1)}%`:"N/A",C.accentText],
              ["Published",d.published_date||"?",C.muted],["Modified",d.modified_date||"?",C.muted],
              ["CWE",d.cwe||"N/A",C.purple],
              ["KEV Status",d.kev_listed?`Listed ${d.kev_date||""}`:"Not Listed",d.kev_listed?C.red:C.muted],
            ].map(([label,value,color])=>(
              <div key={label} style={{background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:8,padding:12}}>
                <div style={{fontSize:10,color:C.muted,fontWeight:700,marginBottom:4,letterSpacing:.5,textTransform:"uppercase"}}>{label}</div>
                <div style={{fontSize:13,color,fontWeight:600}}>{value}</div>
              </div>
            ))}
          </div>
          {d.patch_available&&(
            <div style={{background:C.green+"10",border:`1px solid ${C.green}30`,borderRadius:10,padding:14,marginBottom:16}}>
              <div style={{fontSize:12,fontWeight:700,color:C.green,marginBottom:6}}>✅ Patch Available</div>
              {d.patch_detected_at&&<div style={{fontSize:11,color:C.muted,marginBottom:8}}>Detected: {new Date(d.patch_detected_at).toLocaleString()}</div>}
              {d.patch_url&&<a href={d.patch_url} target="_blank" rel="noreferrer" style={{fontSize:12,color:C.green,fontWeight:600,display:"inline-block",padding:"4px 14px",border:`1px solid ${C.green}40`,borderRadius:6}}>View Vendor Patch / Advisory →</a>}
            </div>
          )}
          {d.affected_versions&&(
            <div style={{marginBottom:16}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:8,letterSpacing:.5,textTransform:"uppercase"}}>Affected Versions</div>
              <div style={{fontSize:12,color:C.text,padding:"8px 12px",background:C.surfaceHi,borderRadius:6,fontFamily:"monospace"}}>{d.affected_versions}</div>
            </div>
          )}
          {d.cvss_vector&&(
            <div style={{marginBottom:16}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:8,letterSpacing:.5,textTransform:"uppercase"}}>CVSS Vector</div>
              <div style={{fontSize:11,color:C.accentText,padding:"8px 12px",background:C.surfaceHi,borderRadius:6,fontFamily:"monospace",wordBreak:"break-all"}}>{d.cvss_vector}</div>
            </div>
          )}
          {detail?.linked_iocs?.length>0&&(
            <div style={{marginBottom:16}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:8,letterSpacing:.5,textTransform:"uppercase"}}>Auto-Extracted IOCs ({detail.linked_iocs.length})</div>
              <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                {detail.linked_iocs.map(ioc=>(
                  <span key={ioc.id} style={{fontSize:11,padding:"3px 10px",borderRadius:4,background:C.accentDim,color:C.accentText,border:`1px solid ${C.accent}40`,fontFamily:"monospace"}}>{ioc.value_defanged||ioc.value}</span>
                ))}
              </div>
            </div>
          )}
          {d.references?.length>0&&(
            <div>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:8,letterSpacing:.5,textTransform:"uppercase"}}>References</div>
              {d.references.slice(0,8).map((ref,i)=>(
                <div key={i} style={{marginBottom:6,display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
                  <a href={ref.url} target="_blank" rel="noreferrer" style={{fontSize:12,color:C.accentText,wordBreak:"break-all",flex:1}}>{ref.url}</a>
                  {ref.tags?.map(tag=><span key={tag} style={{fontSize:10,padding:"1px 6px",borderRadius:3,background:C.surfaceHi,color:C.muted,border:`1px solid ${C.border}`,whiteSpace:"nowrap"}}>{tag}</span>)}
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
function AssetManager({token,C,onChanged}){
  const [assets,setAssets]=useState([]);
  const [form,setForm]=useState({name:"",vendor:"",version:"",asset_type:"application",criticality:"high",cpe:"",description:""});
  const [cpeSearch,setCpeSearch]=useState(""); const [cpeSuggestions,setCpeSuggestions]=useState([]);
  const [cpeLoading,setCpeLoading]=useState(false); const [saving,setSaving]=useState(false); const [msg,setMsg]=useState("");
  const ASSET_TYPES=["application","os","firmware","cloud_service","hardware","library","database"];
  const CRITICALITIES=["critical","high","medium","low"];

  const load=useCallback(()=>api("/assets",{},token).then(r=>r.ok?r.json():[]).then(setAssets),[token]);
  useEffect(()=>{load();},[load]);

  async function searchCPE(){
    if(!cpeSearch.trim())return;setCpeLoading(true);
    const r=await api(`/assets/cpe-search?q=${encodeURIComponent(cpeSearch)}`,{},token);
    if(r.ok){const d=await r.json();setCpeSuggestions(d.results||[]);}
    setCpeLoading(false);
  }
  async function addAsset(){
    if(!form.name.trim())return;setSaving(true);setMsg("");
    const r=await api("/assets",{method:"POST",body:JSON.stringify(form)},token);
    if(r.ok){setMsg("Asset added. CVE monitoring starts at next poll.");setForm({name:"",vendor:"",version:"",asset_type:"application",criticality:"high",cpe:"",description:""});setCpeSuggestions([]);setCpeSearch("");load();if(onChanged)onChanged();}
    setSaving(false);
  }
  async function removeAsset(id){
    await api(`/assets/${id}`,{method:"DELETE"},token);load();if(onChanged)onChanged();
  }

  return(
    <div style={{maxWidth:800}}>
      <Card C={C} style={{marginBottom:24}}>
        <div style={{fontSize:13,fontWeight:700,color:C.white,marginBottom:16}}>Add Software / Service to Monitor</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
          <Field label="Name *" C={C}><Inp value={form.name} onChange={v=>setForm(p=>({...p,name:v}))} placeholder="e.g. Apache Log4j" C={C}/></Field>
          <Field label="Vendor" C={C}><Inp value={form.vendor} onChange={v=>setForm(p=>({...p,vendor:v}))} placeholder="e.g. Apache" C={C}/></Field>
          <Field label="Version" C={C}><Inp value={form.version} onChange={v=>setForm(p=>({...p,version:v}))} placeholder="e.g. 2.14.1 (blank = all versions)" C={C}/></Field>
          <Field label="Type" C={C}>
            <select value={form.asset_type} onChange={e=>setForm(p=>({...p,asset_type:e.target.value}))} style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"10px 12px",borderRadius:8,fontSize:14,outline:"none",fontFamily:"inherit"}}>
              {ASSET_TYPES.map(t=><option key={t} value={t}>{t.replace("_"," ")}</option>)}
            </select>
          </Field>
        </div>
        <Field label="CPE Identifier (required for NVD matching)" C={C}>
          <Inp value={form.cpe} onChange={v=>setForm(p=>({...p,cpe:v}))} placeholder="e.g. cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" C={C}/>
          <div style={{display:"flex",gap:8,marginTop:8}}>
            <input value={cpeSearch} onChange={e=>setCpeSearch(e.target.value)} onKeyDown={e=>{if(e.key==="Enter")searchCPE();}}
              placeholder="Search NVD CPE dictionary (e.g. 'log4j', 'nginx')..."
              style={{flex:1,background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"8px 12px",borderRadius:8,fontSize:13,outline:"none",fontFamily:"inherit"}}/>
            <Btn onClick={searchCPE} disabled={cpeLoading||!cpeSearch.trim()} variant="dim" C={C} sm>{cpeLoading?"Searching...":"Search CPE"}</Btn>
          </div>
          {cpeSuggestions.length>0&&(
            <div style={{background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:8,marginTop:6,overflow:"hidden"}}>
              {cpeSuggestions.map((s,i)=>(
                <div key={i} onClick={()=>{setForm(p=>({...p,cpe:s.cpe}));setCpeSuggestions([]);}}
                  style={{padding:"10px 14px",cursor:"pointer",borderBottom:i<cpeSuggestions.length-1?`1px solid ${C.border}`:"none"}}
                  onMouseEnter={e=>e.currentTarget.style.background=C.surface}
                  onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                  <div style={{fontSize:12,color:C.accentText,fontFamily:"monospace"}}>{s.cpe}</div>
                  {s.title&&<div style={{fontSize:11,color:C.muted,marginTop:2}}>{s.title}</div>}
                </div>
              ))}
            </div>
          )}
        </Field>
        {msg&&<div style={{fontSize:12,color:C.green,marginBottom:12,padding:"8px 12px",background:C.green+"10",borderRadius:6,border:`1px solid ${C.green}30`}}>{msg}</div>}
        <Btn onClick={addAsset} disabled={!form.name.trim()||saving} C={C}>{saving?"Adding...":"Add to Monitor List"}</Btn>
      </Card>
      <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:1.5,textTransform:"uppercase",marginBottom:12}}>Monitored Assets ({assets.length})</div>
      {assets.length===0&&<div style={{textAlign:"center",padding:40,color:C.muted,fontSize:13,background:C.surface,border:`1px solid ${C.border}`,borderRadius:12}}>No assets yet. Add software above to start CVE monitoring.</div>}
      {assets.map(asset=>(
        <div key={asset.id} style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:18,marginBottom:12,boxShadow:C.shadow}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",flexWrap:"wrap",gap:8}}>
            <div>
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4,flexWrap:"wrap"}}>
                <span style={{fontSize:15,fontWeight:700,color:C.white}}>{asset.name}</span>
                {asset.vendor&&<span style={{fontSize:12,color:C.muted}}>{asset.vendor}</span>}
                {asset.version&&<span style={{fontSize:11,padding:"1px 6px",borderRadius:3,background:C.badge,color:C.muted,fontFamily:"monospace"}}>v{asset.version}</span>}
                <span style={{fontSize:11,padding:"1px 6px",borderRadius:3,background:C.surfaceHi,color:C.accentText}}>{asset.asset_type?.replace("_"," ")}</span>
              </div>
              {asset.cpe&&<div style={{fontSize:11,color:C.muted,fontFamily:"monospace",marginBottom:6}}>{asset.cpe}</div>}
              <div style={{display:"flex",gap:12,fontSize:12,flexWrap:"wrap"}}>
                <span style={{color:C.text}}>{asset.cve_count||0} CVEs found</span>
                {(asset.kev_unpatched||0)>0&&<span style={{color:C.red,fontWeight:700}}>🚨 {asset.kev_unpatched} KEV unpatched</span>}
                {(asset.critical_unpatched||0)>0&&<span style={{color:C.amber,fontWeight:600}}>⚠ {asset.critical_unpatched} critical unpatched</span>}
              </div>
            </div>
            <Btn onClick={()=>removeAsset(asset.id)} variant="danger" C={C} sm>Remove</Btn>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── CVE DASHBOARD ─────────────────────────────────────────────────────────────
function CVEDashboard({token,C}){
  const [cves,setCves]=useState([]); const [summary,setSummary]=useState(null);
  const [selectedCVE,setSelectedCVE]=useState(null); const [loading,setLoading]=useState(false);
  const [polling,setPolling]=useState(false); const [pollResult,setPollResult]=useState(null);
  const [filterPatch,setFilterPatch]=useState("all"); const [filterKEV,setFilterKEV]=useState(false);
  const [filterAsset,setFilterAsset]=useState("all"); const [assets,setAssets]=useState([]);
  const [subView,setSubView]=useState("cves");

  const fetchData=useCallback(async()=>{
    setLoading(true);
    const [cvesRes,summaryRes]=await Promise.all([api("/cves",{},token),api("/cves/stats/summary",{},token)]);
    if(cvesRes.ok)setCves(await cvesRes.json());
    if(summaryRes.ok)setSummary(await summaryRes.json());
    setLoading(false);
  },[token]);

  useEffect(()=>{fetchData();api("/assets",{},token).then(r=>r.ok?r.json():[]).then(setAssets);},[token,fetchData]);

  async function pollNow(){
    setPolling(true);setPollResult(null);
    const r=await api("/cves/poll-now",{method:"POST"},token);
    if(r.ok){const d=await r.json();setPollResult(d);await fetchData();}
    setPolling(false);
  }

  const filtered=cves.filter(c=>{
    if(filterPatch==="patched"&&!c.patch_available)return false;
    if(filterPatch==="unpatched"&&c.patch_available)return false;
    if(filterKEV&&!c.kev_listed)return false;
    if(filterAsset!=="all"&&c.asset_id!==filterAsset)return false;
    return true;
  });

  return(
    <div>
      {selectedCVE&&<CVEDetail cve={selectedCVE} token={token} onClose={()=>setSelectedCVE(null)} C={C}/>}
      <div style={{display:"flex",gap:4,marginBottom:20,background:C.surfaceHi,borderRadius:10,padding:3,width:"fit-content"}}>
        {[["cves","CVE Feed"],["assets","Asset Registry"]].map(([id,label])=>(
          <button key={id} onClick={()=>setSubView(id)} style={{padding:"8px 18px",borderRadius:8,border:"none",cursor:"pointer",fontSize:13,fontFamily:"inherit",fontWeight:600,background:subView===id?C.accent:"transparent",color:subView===id?"#fff":C.muted}}>
            {label}
          </button>
        ))}
      </div>

      {subView==="assets"&&<AssetManager token={token} C={C} onChanged={()=>{fetchData();api("/assets",{},token).then(r=>r.ok?r.json():[]).then(setAssets);}}/>}

      {subView==="cves"&&(
        <>
          {summary&&(
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:12,marginBottom:20}}>
              {[["Total CVEs",summary.total,C.accentText],["Unpatched",summary.unpatched,C.red],["Patched",summary.patched,C.green],["KEV Unpatched",summary.kev_unpatched,C.red],["Critical Unpatched",summary.critical_unpatched,C.amber]].map(([label,val,color])=>(
                <StatCard key={label} label={label} value={val||0} color={color} C={C}/>
              ))}
            </div>
          )}
          {summary?.last_poll&&<div style={{fontSize:11,color:C.muted,marginBottom:14}}>Last poll: {new Date(summary.last_poll).toLocaleString()} · Polls every 6 hours automatically</div>}

          <div style={{display:"flex",gap:8,marginBottom:16,flexWrap:"wrap",alignItems:"center"}}>
            <div style={{display:"flex",gap:3,background:C.surfaceHi,borderRadius:8,padding:3}}>
              {[["all","All"],["unpatched","Unpatched"],["patched","Patched"]].map(([val,label])=>(
                <button key={val} onClick={()=>setFilterPatch(val)} style={{padding:"6px 14px",borderRadius:6,border:"none",cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600,background:filterPatch===val?C.accent:"transparent",color:filterPatch===val?"#fff":C.muted}}>{label}</button>
              ))}
            </div>
            <label style={{display:"flex",alignItems:"center",gap:5,fontSize:12,color:C.muted,cursor:"pointer"}}>
              <input type="checkbox" checked={filterKEV} onChange={e=>setFilterKEV(e.target.checked)} style={{accentColor:C.accent}}/>KEV Only
            </label>
            <select value={filterAsset} onChange={e=>setFilterAsset(e.target.value)} style={{background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"7px 10px",borderRadius:8,fontSize:12,outline:"none",fontFamily:"inherit"}}>
              <option value="all">All Assets</option>
              {assets.map(a=><option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
            <div style={{marginLeft:"auto",display:"flex",gap:8}}>
              <button onClick={fetchData} style={{padding:"7px 14px",background:"none",border:`1px solid ${C.border}`,color:C.muted,borderRadius:8,cursor:"pointer",fontSize:12,fontFamily:"inherit"}}>↻ Refresh</button>
              <button onClick={pollNow} disabled={polling} style={{padding:"7px 14px",background:polling?C.accentDim:C.accent,border:"none",color:"#fff",borderRadius:8,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:700,opacity:polling?0.6:1}}>
                {polling?"Polling NVD...":"⟳ Poll Now"}
              </button>
            </div>
          </div>

          {pollResult&&(
            <div style={{marginBottom:16,padding:14,background:C.green+"10",border:`1px solid ${C.green}30`,borderRadius:10,fontSize:13,color:C.text}}>
              <strong style={{color:C.green}}>Poll complete</strong> — {pollResult.new_cves} new CVEs · {pollResult.new_iocs} IOCs auto-added · {pollResult.patches_detected} patches detected · {pollResult.assets_polled} assets scanned
              {pollResult.message&&<span style={{color:C.muted}}> · {pollResult.message}</span>}
            </div>
          )}

          {loading?(
            <div style={{textAlign:"center",padding:60,color:C.muted}}>Loading CVEs...</div>
          ):filtered.length===0?(
            <div style={{textAlign:"center",padding:60,background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,color:C.muted}}>
              <div style={{fontSize:32,marginBottom:12}}>🛡️</div>
              <div style={{fontSize:14,fontWeight:600,color:C.white,marginBottom:8}}>No CVEs found</div>
              <div style={{fontSize:13,marginBottom:16}}>{assets.length===0?"Add software to your Asset Registry to start monitoring.":"No CVEs match your current filters. Try Poll Now to fetch the latest data."}</div>
              <Btn onClick={()=>setSubView("assets")} C={C}>{assets.length===0?"Go to Asset Registry":"Check Filters"}</Btn>
            </div>
          ):(
            <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,overflow:"hidden",boxShadow:C.shadow}}>
              <div style={{overflowX:"auto"}}>
                <table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}>
                  <thead>
                    <tr style={{background:C.surfaceHi,borderBottom:`1px solid ${C.border}`}}>
                      {["CVE","Asset","Severity","EPSS","KEV","Patch Status","Published",""].map(h=>(
                        <th key={h} style={{padding:"10px 12px",textAlign:"left",color:C.muted,fontSize:11,fontWeight:700,whiteSpace:"nowrap",letterSpacing:.5}}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((cve,idx)=>(
                      <tr key={cve.id||cve.cve_id} onClick={()=>setSelectedCVE(cve)}
                        style={{borderBottom:`1px solid ${C.border}20`,cursor:"pointer",background:cve.kev_listed?C.red+"06":idx%2===0?"transparent":C.surfaceHi+"40"}}
                        onMouseEnter={e=>e.currentTarget.style.background=C.surfaceHi}
                        onMouseLeave={e=>e.currentTarget.style.background=cve.kev_listed?C.red+"06":idx%2===0?"transparent":C.surfaceHi+"40"}>
                        <td style={{padding:"10px 12px"}}>
                          <div style={{fontFamily:"monospace",fontSize:12,color:C.accentText,fontWeight:700}}>{cve.cve_id}</div>
                          {cve.kev_listed&&<div style={{fontSize:10,color:C.red,fontWeight:700,marginTop:2}}>🚨 CISA KEV</div>}
                        </td>
                        <td style={{padding:"10px 12px",color:C.text,fontSize:12,fontWeight:500}}>{cve.asset_name||"?"}</td>
                        <td style={{padding:"10px 12px"}}><SevBadge severity={cve.cvss_severity} score={cve.cvss_score} C={C}/></td>
                        <td style={{padding:"10px 12px"}}>
                          {cve.epss_score!=null?(
                            <div>
                              <div style={{fontSize:12,fontWeight:700,color:cve.epss_score>=0.5?C.red:cve.epss_score>=0.1?C.amber:C.muted}}>{(cve.epss_score*100).toFixed(1)}%</div>
                              <div style={{fontSize:10,color:C.muted}}>exploit prob.</div>
                            </div>
                          ):<span style={{color:C.muted,fontSize:11}}>N/A</span>}
                        </td>
                        <td style={{padding:"10px 12px"}}>{cve.kev_listed?<span style={{fontSize:11,fontWeight:700,color:C.red}}>Yes</span>:<span style={{fontSize:11,color:C.muted}}>No</span>}</td>
                        <td style={{padding:"10px 12px"}}><PatchBadge available={cve.patch_available} url={cve.patch_url} C={C}/></td>
                        <td style={{padding:"10px 12px",fontSize:11,color:C.muted,whiteSpace:"nowrap"}}>{cve.published_date||"?"}</td>
                        <td style={{padding:"10px 12px"}}><span style={{fontSize:11,color:C.accentText,cursor:"pointer"}}>→</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div style={{padding:"8px 14px",borderTop:`1px solid ${C.border}`,fontSize:11,color:C.muted,display:"flex",justifyContent:"space-between"}}>
                <span>Click any row for full details, linked IOCs, references, patch info</span>
                <span>{filtered.length} of {cves.length} CVEs · Sorted by KEV + CVSS</span>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── RELATIONSHIP GRAPH ────────────────────────────────────────────────────────
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

  useEffect(()=>{setPos(p=>{const next={...p};nodeList.forEach((n,i)=>{if(!next[n.id]){const angle=(i/Math.max(nodeList.length,1))*Math.PI*2;next[n.id]=n.isCenter?{x:300,y:190}:{x:300+Math.cos(angle)*130,y:190+Math.sin(angle)*100};}});return next;});},[rels]);

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
  },[rels]);

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
function IntelNews({token,C}){
  const [news,setNews]=useState([]); const [loading,setLoading]=useState(false); const [err,setErr]=useState(""); const [category,setCategory]=useState("all");
  async function fetchNews(){
    setLoading(true);setErr("");setNews([]);
    const r=await api("/ai/intel-news",{method:"POST",body:JSON.stringify({category})},token);
    if(r.ok){const d=await r.json();setNews(d.items||[]);}
    else setErr("Failed to fetch news — check backend logs.");
    setLoading(false);
  }
  const SEV_COLORS={Critical:C.red,High:C.amber,Medium:C.purple,Low:C.green};
  const CAT_COLORS={CVE:C.red,APT:C.purple,Ransomware:C.amber,Malware:C.amber,"Data Breach":C.red,Other:C.muted};
  return(
    <div>
      <div style={{display:"flex",gap:10,marginBottom:20,flexWrap:"wrap",alignItems:"center"}}>
        <div style={{display:"flex",gap:4,background:C.surfaceHi,borderRadius:10,padding:3}}>
          {["all","cve","apt","ransomware","ioc"].map(t=>(
            <button key={t} onClick={()=>setCategory(t)} style={{padding:"7px 14px",borderRadius:7,border:"none",cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600,background:category===t?C.accent:"transparent",color:category===t?"#fff":C.muted}}>{t.toUpperCase()}</button>
          ))}
        </div>
        <Btn onClick={fetchNews} disabled={loading} C={C}>{loading?"Fetching...":"⟳ Refresh Intel"}</Btn>
      </div>
      {!loading&&news.length===0&&!err&&(
        <div style={{textAlign:"center",padding:48,color:C.muted}}>
          <div style={{fontSize:32,marginBottom:12}}>🌐</div>
          <div style={{fontSize:14,fontWeight:600,color:C.white,marginBottom:8}}>Cyber Intelligence Wall</div>
          <div style={{fontSize:13,marginBottom:20}}>Click Refresh Intel to pull the latest threat intelligence from CISA, SANS ISC, BleepingComputer, and Krebs on Security.</div>
          <Btn onClick={fetchNews} C={C}>Fetch Latest Intel</Btn>
        </div>
      )}
      {err&&<div style={{padding:14,background:C.red+"10",border:`1px solid ${C.red}30`,borderRadius:8,color:C.red,fontSize:13,marginBottom:16}}>{err}</div>}
      {loading&&<div style={{textAlign:"center",padding:48,color:C.muted,fontSize:14}}>Fetching from CISA, SANS ISC, BleepingComputer, Krebs...</div>}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(300px,1fr))",gap:14}}>
        {news.map((item,i)=>(
          <div key={i} style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:18,boxShadow:C.shadow,display:"flex",flexDirection:"column"}}>
            <div style={{display:"flex",gap:8,marginBottom:10,flexWrap:"wrap"}}>
              <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,background:(CAT_COLORS[item.category]||C.muted)+"20",color:CAT_COLORS[item.category]||C.muted,fontWeight:700}}>{item.category}</span>
              <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,background:(SEV_COLORS[item.severity]||C.muted)+"15",color:SEV_COLORS[item.severity]||C.muted,fontWeight:600}}>{item.severity}</span>
            </div>
            <div style={{fontSize:14,fontWeight:700,color:C.white,marginBottom:8,lineHeight:1.4}}>{item.title}</div>
            <div style={{fontSize:12,color:C.text,lineHeight:1.6,flex:1,marginBottom:12}}>{item.summary}</div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div style={{fontSize:11,color:C.muted}}>{item.source} · {item.date}</div>
              {item.url&&<a href={item.url} target="_blank" rel="noreferrer" style={{fontSize:11,color:C.accentText,fontWeight:600}}>Read →</a>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── THREAT ACTORS ─────────────────────────────────────────────────────────────
function ThreatActors({token,C}){
  const [query,setQuery]=useState(""); const [result,setResult]=useState(null); const [loading,setLoading]=useState(false); const [err,setErr]=useState("");
  const POPULAR=["Lazarus Group","APT28","APT29","Sandworm","Scattered Spider","Volt Typhoon","Carbanak","Kimsuky","APT41","Turla"];
  async function research(){
    if(!query.trim())return;setLoading(true);setErr("");setResult(null);
    const r=await api(`/mitre/actor?name=${encodeURIComponent(query.trim())}`,{},token);
    if(!r.ok){setErr("Failed to reach MITRE ATT&CK.");setLoading(false);return;}
    const d=await r.json();
    if(d.error)setErr(`Error: ${d.error}`);
    else setResult(d);
    setLoading(false);
  }
  return(
    <div style={{maxWidth:900}}>
      <div style={{marginBottom:16,padding:12,background:C.accentDim,border:`1px solid ${C.accent}28`,borderRadius:10,fontSize:12,color:C.accentText,lineHeight:1.6}}>
        Data sourced from the <strong>MITRE ATT&CK</strong> open-source CTI dataset — no API key required.
      </div>
      <div style={{display:"flex",gap:10,marginBottom:20}}>
        <input value={query} onChange={e=>setQuery(e.target.value)} onKeyDown={e=>{if(e.key==="Enter")research();}} placeholder="Search threat actor or APT group (e.g. Lazarus Group, APT28)..."
          style={{flex:1,background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"12px 16px",borderRadius:10,fontSize:14,outline:"none",fontFamily:"inherit"}}/>
        <Btn onClick={research} disabled={loading||!query.trim()} C={C}>{loading?"Searching...":"Search"}</Btn>
      </div>
      {!result&&!loading&&(
        <div>
          <div style={{fontSize:12,color:C.muted,marginBottom:12,fontWeight:600,letterSpacing:.5}}>CATALOGUED IN MITRE ATT&CK</div>
          <div style={{display:"flex",flexWrap:"wrap",gap:8,marginBottom:24}}>{POPULAR.map(p=><button key={p} onClick={()=>setQuery(p)} style={{padding:"6px 14px",borderRadius:8,border:`1px solid ${C.border}`,background:C.surfaceHi,color:C.text,cursor:"pointer",fontSize:13,fontFamily:"inherit",fontWeight:500}}>{p}</button>)}</div>
        </div>
      )}
      {loading&&<div style={{textAlign:"center",padding:48,color:C.muted,fontSize:14}}>Searching MITRE ATT&CK for <strong style={{color:C.white}}>{query}</strong>...</div>}
      {err&&<div style={{padding:14,background:C.red+"10",border:`1px solid ${C.red}30`,borderRadius:8,color:C.red,fontSize:13}}>{err}</div>}
      {result&&!result.found&&!err&&(
        <div style={{textAlign:"center",padding:48,color:C.muted}}>
          <div style={{fontSize:16,fontWeight:600,color:C.white,marginBottom:8}}>Not found in MITRE ATT&CK</div>
          <div style={{fontSize:13,marginBottom:16}}>Try an alternate alias — e.g. "Fancy Bear" instead of "APT28".</div>
          <a href="https://attack.mitre.org/groups/" target="_blank" rel="noreferrer" style={{color:C.accentText,fontSize:12}}>Browse all groups at attack.mitre.org →</a>
        </div>
      )}
      {result?.found&&(
        <div>
          <Card C={C} style={{marginBottom:16}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:16,flexWrap:"wrap",gap:12}}>
              <div>
                <div style={{fontSize:22,fontWeight:700,color:C.white,marginBottom:6}}>{result.name}</div>
                {result.also_known_as?.length>0&&<div style={{fontSize:12,color:C.muted}}>aka: {result.also_known_as.join(", ")}</div>}
                <div style={{fontSize:11,color:C.accentText,marginTop:6,fontWeight:600}}>Source: MITRE ATT&CK</div>
              </div>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                {result.mitre_url&&<a href={result.mitre_url} target="_blank" rel="noreferrer" style={{fontSize:12,padding:"4px 12px",borderRadius:6,background:C.accentDim,color:C.accentText,fontWeight:600,border:`1px solid ${C.accent}40`}}>View on MITRE →</a>}
              </div>
            </div>
            {result.description&&<div style={{fontSize:13,color:C.text,lineHeight:1.7,padding:14,background:C.surfaceHi,borderRadius:8}}>{result.description.slice(0,600)}{result.description.length>600?"...":""}</div>}
          </Card>
          {result.ttps?.length>0&&<Card C={C} style={{marginBottom:14}}><div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:12,letterSpacing:.5,textTransform:"uppercase"}}>MITRE ATT&CK Techniques ({result.ttps.length})</div><div style={{display:"flex",flexWrap:"wrap",gap:6}}>{result.ttps.map(t=><span key={t} style={{fontSize:11,padding:"3px 10px",borderRadius:4,background:C.purple+"20",color:C.purple,fontWeight:600,border:`1px solid ${C.purple}30`}}>{t}</span>)}</div></Card>}
          {(result.malware_used?.length>0||result.tools_used?.length>0)&&<Card C={C} style={{marginBottom:14}}><div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))",gap:16}}>{result.malware_used?.length>0&&<div><div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:8,textTransform:"uppercase"}}>Malware Used</div><div style={{display:"flex",flexWrap:"wrap",gap:4}}>{result.malware_used.map(m=><span key={m} style={{fontSize:11,padding:"2px 8px",borderRadius:4,background:C.red+"20",color:C.red,border:`1px solid ${C.red}30`}}>{m}</span>)}</div></div>}{result.tools_used?.length>0&&<div><div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:8,textTransform:"uppercase"}}>Tools Used</div><div style={{display:"flex",flexWrap:"wrap",gap:4}}>{result.tools_used.map(t=><span key={t} style={{fontSize:11,padding:"2px 8px",borderRadius:4,background:C.amber+"20",color:C.amber,border:`1px solid ${C.amber}30`}}>{t}</span>)}</div></div>}</div></Card>}
          {result.references?.filter(r=>r).length>0&&<Card C={C}><div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:12,textTransform:"uppercase"}}>References</div>{result.references.filter(r=>r).map((ref,i)=><a key={i} href={ref} target="_blank" rel="noreferrer" style={{display:"block",fontSize:12,color:C.accentText,marginBottom:6,wordBreak:"break-all"}}>{ref}</a>)}</Card>}
        </div>
      )}
    </div>
  );
}

// ── OSINT TOOL ────────────────────────────────────────────────────────────────
function OSINTTool({token,C}){
  const [target,setTarget]=useState(""); const [targetType,setTargetType]=useState("domain");
  const [result,setResult]=useState(null); const [loading,setLoading]=useState(false);
  async function lookup(){if(!target.trim())return;setLoading(true);setResult(null);const r=await api("/osint/lookup",{method:"POST",body:JSON.stringify({target:target.trim(),target_type:targetType})},token);if(r.ok)setResult(await r.json());setLoading(false);}
  return(
    <div style={{maxWidth:800}}>
      <div style={{marginBottom:20,padding:14,background:C.accentDim,border:`1px solid ${C.accent}28`,borderRadius:10,fontSize:13,color:C.accentText,lineHeight:1.6}}>Threat Actor OSINT — DNS records, RDAP/WHOIS, Shodan port scan, and HaveIBeenPwned email breach lookup.</div>
      <div style={{display:"flex",gap:10,marginBottom:24,flexWrap:"wrap"}}>
        <div style={{display:"flex",background:C.surfaceHi,borderRadius:8,padding:3,gap:2}}>
          {[["domain","Domain"],["ip","IP Address"],["email","Email"]].map(([val,label])=>(
            <button key={val} onClick={()=>setTargetType(val)} style={{padding:"8px 14px",borderRadius:6,border:"none",cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600,background:targetType===val?C.accent:"transparent",color:targetType===val?"#fff":C.muted}}>{label}</button>
          ))}
        </div>
        <input value={target} onChange={e=>setTarget(e.target.value)} onKeyDown={e=>{if(e.key==="Enter")lookup();}}
          placeholder={targetType==="email"?"email@example.com":targetType==="ip"?"185.220.101.45":"evil-domain.com"}
          style={{flex:1,background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"10px 14px",borderRadius:8,fontSize:14,outline:"none",fontFamily:"inherit"}}/>
        <Btn onClick={lookup} disabled={loading||!target.trim()} C={C}>{loading?"Querying...":"Lookup"}</Btn>
      </div>
      {result&&(
        <div>
          <div style={{fontSize:13,color:C.muted,marginBottom:16}}>Results for <strong style={{color:C.white}}>{result.target}</strong> · {new Date(result.queried_at).toLocaleString()}</div>
          {result.data?.dns&&Object.keys(result.data.dns).length>0&&(
            <Card C={C} style={{marginBottom:14}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:12,textTransform:"uppercase",letterSpacing:.5}}>DNS Records</div>
              {Object.entries(result.data.dns).map(([type,records])=>(
                <div key={type} style={{marginBottom:12}}>
                  <div style={{fontSize:11,color:C.accentText,fontWeight:700,marginBottom:6}}>{type}</div>
                  {records.map((r,i)=><div key={i} style={{fontSize:12,color:C.text,padding:"4px 10px",background:C.surfaceHi,borderRadius:4,marginBottom:3,fontFamily:"monospace"}}>{r}</div>)}
                </div>
              ))}
            </Card>
          )}
          {result.data?.rdap&&(
            <Card C={C} style={{marginBottom:14}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:12,textTransform:"uppercase",letterSpacing:.5}}>RDAP / WHOIS</div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:12}}>
                {Object.entries(result.data.rdap).filter(([,v])=>v&&v!=="?").map(([k,v])=>(
                  <div key={k}><div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:2,textTransform:"uppercase"}}>{k.replace(/_/g," ")}</div><div style={{fontSize:12,color:C.text,fontWeight:500}}>{Array.isArray(v)?v.join(", "):String(v)}</div></div>
                ))}
              </div>
            </Card>
          )}
          {result.data?.shodan&&(
            <Card C={C} style={{marginBottom:14}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:12,textTransform:"uppercase",letterSpacing:.5}}>Shodan</div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:12,marginBottom:12}}>
                {[["Org",result.data.shodan.org],["ISP",result.data.shodan.isp],["Country",result.data.shodan.country],["Last Update",result.data.shodan.last_update]].filter(([,v])=>v&&v!=="?").map(([k,v])=>(
                  <div key={k}><div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:2}}>{k}</div><div style={{fontSize:12,color:C.text}}>{v}</div></div>
                ))}
              </div>
              {result.data.shodan.ports?.length>0&&<div style={{marginBottom:10}}><div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:6}}>OPEN PORTS</div><div style={{display:"flex",flexWrap:"wrap",gap:6}}>{result.data.shodan.ports.map(p=><span key={p} style={{fontSize:11,padding:"2px 8px",borderRadius:4,background:C.red+"20",color:C.red,fontFamily:"monospace",fontWeight:700}}>{p}</span>)}</div></div>}
              {result.data.shodan.vulns?.length>0&&<div><div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:6}}>VULNERABILITIES</div><div style={{display:"flex",flexWrap:"wrap",gap:6}}>{result.data.shodan.vulns.map(v=><span key={v} style={{fontSize:11,padding:"2px 8px",borderRadius:4,background:C.amber+"20",color:C.amber,fontFamily:"monospace",fontWeight:600}}>{v}</span>)}</div></div>}
            </Card>
          )}
          {result.data?.hibp&&(
            <Card C={C} style={{marginBottom:14}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:12,textTransform:"uppercase",letterSpacing:.5}}>HaveIBeenPwned</div>
              {result.data.hibp.skipped?(
                <div style={{fontSize:12,color:C.muted,lineHeight:1.7}}>HIBP API key not configured.<br/>Add <code style={{color:C.accentText}}>HIBP_API_KEY=your-key</code> to <code style={{color:C.accentText}}>.env</code>. Get a free key at <a href="https://haveibeenpwned.com/API/Key" target="_blank" rel="noreferrer" style={{color:C.accentText}}>haveibeenpwned.com/API/Key</a></div>
              ):result.data.hibp.breached?(
                <><div style={{fontSize:14,fontWeight:700,color:C.red,marginBottom:12}}>⚠ Found in {result.data.hibp.breach_count} data breaches</div>
                {result.data.hibp.breaches?.map(b=>(
                  <div key={b.name} style={{background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:8,padding:12,marginBottom:8}}>
                    <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}><span style={{fontSize:13,fontWeight:700,color:C.white}}>{b.name}</span><span style={{fontSize:11,color:C.muted}}>{b.date}</span></div>
                    <div style={{display:"flex",flexWrap:"wrap",gap:4}}>{b.data_classes?.map(dc=><span key={dc} style={{fontSize:10,padding:"1px 6px",borderRadius:3,background:C.red+"20",color:C.red,fontWeight:600}}>{dc}</span>)}</div>
                  </div>
                ))}</>
              ):<div style={{fontSize:13,color:C.green,fontWeight:600}}>✓ Not found in any known data breaches</div>}
            </Card>
          )}
          {result.data?.email_domain_mx?.length>0&&(
            <Card C={C}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:12,textTransform:"uppercase",letterSpacing:.5}}>Email Domain MX Records</div>
              {result.data.email_domain_mx.map((mx,i)=><div key={i} style={{fontSize:12,color:C.text,padding:"4px 10px",background:C.surfaceHi,borderRadius:4,marginBottom:4,fontFamily:"monospace"}}>{mx}</div>)}
            </Card>
          )}
          {result.data&&Object.keys(result.data).length===0&&<div style={{padding:32,textAlign:"center",color:C.muted,fontSize:13}}>No data returned. Check your target and type.</div>}
        </div>
      )}
    </div>
  );
}

// ── GLOBAL SEARCH ─────────────────────────────────────────────────────────────
// ── SPL / KQL GENERATOR ───────────────────────────────────────────────────────
function QueryGenerator({token,C}){
  const [queryType,setQueryType]=useState("kql");
  const [useCase,setUseCase]=useState("");
  const [context,setContext]=useState("");
  const [result,setResult]=useState(null);
  const [loading,setLoading]=useState(false);
  const [err,setErr]=useState("");
  const [copied,setCopied]=useState(false);

  const EXAMPLES={
    kql:[
      "Detect brute force login attempts against Azure AD",
      "Find PowerShell downloading files from the internet",
      "Alert on lateral movement using PsExec",
      "Detect DNS tunneling via unusually long queries",
      "Hunt for LOLBin execution (certutil, mshta, wscript)",
      "Detect privilege escalation via token impersonation",
      "Find failed MFA attempts followed by successful login",
    ],
    spl:[
      "Detect multiple failed SSH logins from same IP",
      "Alert on large outbound data transfers",
      "Find new admin accounts created on Windows hosts",
      "Detect Mimikatz-style credential dumping",
      "Hunt for beaconing via regular outbound intervals",
      "Alert on processes spawning cmd.exe or powershell.exe",
      "Detect web shell activity on IIS servers",
    ],
  };

  async function generate(){
    if(!useCase.trim())return;
    setLoading(true);setErr("");setResult(null);setCopied(false);
    const r=await api("/query-gen/generate",{method:"POST",
      body:JSON.stringify({use_case:useCase,query_type:queryType,context})},token);
    if(r.ok){setResult(await r.json());}
    else{const e=await r.json();setErr(e.detail||"Generation failed.");}
    setLoading(false);
  }

  function copy(){
    if(!result?.query)return;
    navigator.clipboard.writeText(result.query);
    setCopied(true);setTimeout(()=>setCopied(false),2000);
  }

  return(
    <div style={{maxWidth:900}}>
      {/* Header */}
      <div style={{marginBottom:20,padding:14,background:C.accentDim,
        border:`1px solid ${C.accent}28`,borderRadius:10,fontSize:13,
        color:C.accentText,lineHeight:1.6}}>
        Generate detection and hunting queries for <strong>Splunk (SPL)</strong> or{" "}
        <strong>Microsoft Sentinel / Defender (KQL)</strong>. Powered by Groq — free, no API quota used on your end.
      </div>

      {/* Type selector */}
      <div style={{display:"flex",gap:4,background:C.surfaceHi,borderRadius:10,
        padding:3,width:"fit-content",marginBottom:20}}>
        {[["kql","KQL","Microsoft Sentinel / Defender"],["spl","SPL","Splunk"]].map(([t,label,sub])=>(
          <button key={t} onClick={()=>{setQueryType(t);setResult(null);setErr("");}}
            style={{padding:"10px 20px",borderRadius:8,border:"none",cursor:"pointer",
              fontFamily:"inherit",fontWeight:700,transition:"all .15s",
              background:queryType===t?C.accent:"transparent",
              color:queryType===t?"#fff":C.muted}}>
            <div style={{fontSize:13}}>{label}</div>
            <div style={{fontSize:10,opacity:.7,fontWeight:400}}>{sub}</div>
          </button>
        ))}
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 300px",gap:20,alignItems:"start"}}>
        {/* Left — input */}
        <div>
          <Field label="Describe your use case or detection goal" C={C}>
            <textarea value={useCase} onChange={e=>setUseCase(e.target.value)}
              rows={4} placeholder={`e.g. "${EXAMPLES[queryType][0]}"`}
              style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                color:C.inputText,padding:"12px 14px",borderRadius:8,fontSize:14,
                outline:"none",fontFamily:"inherit",resize:"vertical",boxSizing:"border-box"}}/>
          </Field>
          <Field label="Additional context (optional)" C={C}>
            <input value={context} onChange={e=>setContext(e.target.value)}
              placeholder="e.g. field names, log sources, index names, specific product versions..."
              style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                color:C.inputText,padding:"10px 14px",borderRadius:8,fontSize:13,
                outline:"none",fontFamily:"inherit",boxSizing:"border-box"}}/>
          </Field>
          <Btn onClick={generate} disabled={!useCase.trim()||loading} C={C}>
            {loading?`Generating ${queryType.toUpperCase()}...`:`Generate ${queryType.toUpperCase()} Query`}
          </Btn>
          {err&&(
            <div style={{marginTop:12,padding:"10px 14px",background:C.red+"10",
              border:`1px solid ${C.red}30`,borderRadius:8,fontSize:13,color:C.red}}>
              {err}
            </div>
          )}
        </div>

        {/* Right — examples */}
        <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:16,boxShadow:C.shadow}}>
          <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:.5,
            textTransform:"uppercase",marginBottom:12}}>Example Prompts</div>
          {EXAMPLES[queryType].map((ex,i)=>(
            <div key={i} onClick={()=>{setUseCase(ex);setResult(null);}}
              style={{fontSize:12,color:C.text,padding:"8px 10px",borderRadius:6,
                cursor:"pointer",marginBottom:4,lineHeight:1.4,transition:"background .1s",
                border:`1px solid transparent`}}
              onMouseEnter={e=>{e.currentTarget.style.background=C.surfaceHi;e.currentTarget.style.borderColor=C.border;}}
              onMouseLeave={e=>{e.currentTarget.style.background="transparent";e.currentTarget.style.borderColor="transparent";}}>
              {ex}
            </div>
          ))}
        </div>
      </div>

      {/* Result */}
      {result&&(
        <div style={{marginTop:24}}>
          {/* Query block */}
          <div style={{background:C.bg,border:`1px solid ${C.border}`,borderRadius:12,
            overflow:"hidden",boxShadow:C.shadow,marginBottom:16}}>
            <div style={{padding:"12px 16px",borderBottom:`1px solid ${C.border}`,
              display:"flex",justifyContent:"space-between",alignItems:"center",
              background:C.surfaceHi}}>
              <div style={{display:"flex",alignItems:"center",gap:10}}>
                <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,
                  background:queryType==="kql"?C.purple+"30":C.amber+"30",
                  color:queryType==="kql"?C.purple:C.amber,
                  border:`1px solid ${queryType==="kql"?C.purple:C.amber}40`}}>
                  {queryType.toUpperCase()}
                </span>
                <span style={{fontSize:12,color:C.muted}}>Generated query</span>
              </div>
              <button onClick={copy} style={{padding:"5px 14px",background:copied?C.green+"20":C.accentDim,
                border:`1px solid ${copied?C.green:C.accent}40`,color:copied?C.green:C.accentText,
                borderRadius:6,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600,
                transition:"all .2s"}}>
                {copied?"✓ Copied!":"Copy Query"}
              </button>
            </div>
            <pre style={{margin:0,padding:"16px 18px",fontSize:13,color:C.accentText,
              fontFamily:"'Space Mono',monospace",overflowX:"auto",lineHeight:1.6,
              whiteSpace:"pre-wrap",wordBreak:"break-word"}}>
              {result.query}
            </pre>
          </div>

          {/* Explanation */}
          {result.explanation&&(
            <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
              padding:18,marginBottom:14,boxShadow:C.shadow}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:.5,
                textTransform:"uppercase",marginBottom:10}}>How it works</div>
              <div style={{fontSize:13,color:C.text,lineHeight:1.8,whiteSpace:"pre-line"}}>
                {result.explanation}
              </div>
            </div>
          )}

          {/* Notes */}
          {result.notes&&(
            <div style={{background:C.amber+"08",border:`1px solid ${C.amber}30`,
              borderRadius:12,padding:18,boxShadow:C.shadow}}>
              <div style={{fontSize:11,color:C.amber,fontWeight:700,letterSpacing:.5,
                textTransform:"uppercase",marginBottom:10}}>⚠ Tuning Notes</div>
              <div style={{fontSize:13,color:C.text,lineHeight:1.8,whiteSpace:"pre-line"}}>
                {result.notes}
              </div>
            </div>
          )}

          {/* Regenerate */}
          <div style={{marginTop:16,display:"flex",gap:8}}>
            <Btn onClick={generate} variant="ghost" C={C} disabled={loading}>
              {loading?"Regenerating...":"↻ Regenerate"}
            </Btn>
            <Btn onClick={()=>{setUseCase("");setResult(null);setContext("");}} variant="ghost" C={C}>
              New Query
            </Btn>
          </div>
        </div>
      )}
    </div>
  );
}

function GlobalSearch({token,C,onSelect}){
  const [q,setQ]=useState(""); const [results,setResults]=useState(null); const [loading,setLoading]=useState(false); const [open,setOpen]=useState(false);
  const ref=useRef(null);
  useEffect(()=>{const h=e=>{if(ref.current&&!ref.current.contains(e.target))setOpen(false);};document.addEventListener("mousedown",h);return()=>document.removeEventListener("mousedown",h);},[]);
  async function search(){if(!q.trim())return;setLoading(true);setOpen(true);const r=await api(`/iocs/search?q=${encodeURIComponent(q)}`,{},token);if(r.ok)setResults(await r.json());setLoading(false);}
  return(
    <div ref={ref} style={{position:"relative",maxWidth:440,width:"100%"}}>
      <div style={{display:"flex",gap:6}}>
        <input value={q} onChange={e=>setQ(e.target.value)} onKeyDown={e=>{if(e.key==="Enter")search();}} placeholder="Global IOC search..."
          style={{flex:1,background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"8px 14px",borderRadius:8,fontSize:13,outline:"none",fontFamily:"inherit"}}/>
        <button onClick={search} style={{padding:"8px 16px",background:C.accent,border:"none",color:"#fff",borderRadius:8,cursor:"pointer",fontSize:14,fontWeight:700}}>⌕</button>
      </div>
      {open&&(
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
                  <span style={{fontSize:11,padding:"1px 6px",borderRadius:3,background:C.badge,color:C.accentText,fontWeight:700}}>{ioc.type}</span>
                  <span style={{fontSize:13,color:C.white,fontWeight:500}}>{ioc.value_defanged||ioc.value}</span>
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
  useEffect(()=>{api("/stats/dashboard",{},token).then(r=>r.ok?r.json():null).then(d=>{if(d)setStats(d);});},[token]);
  if(!stats)return <div style={{padding:40,textAlign:"center",color:C.muted}}>Loading dashboard...</div>;
  const VT_LIMIT=500,ABUSE_LIMIT=1000;
  const vtPct=Math.min(100,Math.round((stats.api_usage?.virustotal||0)/VT_LIMIT*100));
  const abusePct=Math.min(100,Math.round((stats.api_usage?.abuseipdb||0)/ABUSE_LIMIT*100));
  return(
    <div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(150px,1fr))",gap:14,marginBottom:24}}>
        <StatCard label="Live IOCs" value={stats.total} color={C.accentText} C={C}/>
        <StatCard label="Expired" value={stats.expired} color={C.amber} C={C}/>
        <StatCard label="False Positives" value={stats.fp_count} color={C.red} C={C}/>
        <StatCard label="High Confidence" value={stats.by_confidence?.find(x=>x.band==="High")?.count||0} color={C.green} C={C}/>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(240px,1fr))",gap:16,marginBottom:20}}>
        {[{title:"By Type",data:stats.by_type,key:"type"},{title:"By Industry",data:stats.by_industry,key:"industry"},{title:"By TLP",data:stats.by_tlp,key:"tlp"},{title:"Top Contributors",data:stats.top_contributors,key:"username"}].map(({title,data,key})=>(
          <div key={title} style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:18,boxShadow:C.shadow}}>
            <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:.5,marginBottom:12,textTransform:"uppercase"}}>{title}</div>
            {(data||[]).slice(0,6).map((row,i)=>{const max=Math.max(...(data||[]).map(x=>x.count),1);return(
              <div key={i} style={{marginBottom:8}}>
                <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}><span style={{fontSize:12,color:C.text,fontWeight:500}}>{key==="tlp"?<TLPBadge level={row[key]}/>:row[key]||"unknown"}</span><span style={{fontSize:12,color:C.muted}}>{row.count}</span></div>
                <div style={{height:3,background:C.border,borderRadius:2,overflow:"hidden"}}><div style={{width:`${(row.count/max)*100}%`,height:"100%",background:C.accent,borderRadius:2}}/></div>
              </div>
            );})}
          </div>
        ))}
      </div>
      <Card C={C}>
        <div style={{fontSize:11,color:C.muted,fontWeight:700,letterSpacing:.5,marginBottom:14,textTransform:"uppercase"}}>API Usage Today</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",gap:16}}>
          {[{name:"VirusTotal",used:stats.api_usage?.virustotal||0,limit:VT_LIMIT,pct:vtPct},{name:"AbuseIPDB",used:stats.api_usage?.abuseipdb||0,limit:ABUSE_LIMIT,pct:abusePct},{name:"URLhaus",used:stats.api_usage?.urlhaus||0,limit:"∞",pct:0}].map(({name,used,limit,pct})=>(
            <div key={name}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:6}}><span style={{fontSize:13,color:C.text,fontWeight:500}}>{name}</span><span style={{fontSize:12,color:pct>=80?C.red:pct>=60?C.amber:C.green,fontWeight:600}}>{used}/{limit}</span></div>
              {limit!=="∞"&&<div style={{height:4,background:C.border,borderRadius:2,overflow:"hidden"}}><div style={{width:`${pct}%`,height:"100%",background:pct>=80?C.red:pct>=60?C.amber:C.green,borderRadius:2}}/></div>}
              {limit==="∞"&&<div style={{fontSize:11,color:C.muted}}>No rate limit</div>}
            </div>
          ))}
        </div>
        <div style={{marginTop:10,fontSize:12,color:C.muted}}>Cache hits today: <span style={{color:C.green,fontWeight:600}}>{stats.api_usage?.cache_hits_today||0}</span> — enrichments cached 24h to preserve API quota.</div>
      </Card>
    </div>
  );
}

// ── SETTINGS ──────────────────────────────────────────────────────────────────
function SettingsPage({themeName,setThemeName,token,onLogout,C,me}){
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
            <button key={key} onClick={()=>{setThemeName(key);localStorage.setItem("tf_theme",key);}} style={{padding:"18px 14px",borderRadius:12,border:`2px solid ${themeName===key?theme.accent:theme.border}`,background:theme.bg,cursor:"pointer",textAlign:"center",transition:"all .2s"}}>
              <div style={{display:"flex",gap:6,justifyContent:"center",marginBottom:10}}>{[theme.accent,theme.green,theme.red,theme.purple].map((col,i)=><div key={i} style={{width:10,height:10,borderRadius:"50%",background:col}}/>)}</div>
              <div style={{fontSize:12,color:theme.white,fontWeight:700}}>{theme.name}</div>
              {themeName===key&&<div style={{fontSize:10,color:theme.accent,marginTop:4,fontWeight:700}}>ACTIVE</div>}
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
  const [themeName,setThemeName]=useState(()=>localStorage.getItem("tf_theme")||"operator");
  const C=THEMES[themeName]||THEMES.operator;
  const [mode,setMode]=useState(()=>localStorage.getItem("tf_mode")||"ioc");
  function switchMode(m){setMode(m);localStorage.setItem("tf_mode",m);setView("dashboard");}
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

  useEffect(()=>{if(!token)return;api("/auth/me",{},token).then(r=>r.ok?r.json():null).then(d=>{if(d)setMe(d);});},[token]);

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
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap');*{box-sizing:border-box;}::-webkit-scrollbar{width:4px;height:4px;}::-webkit-scrollbar-track{background:${C.bg};}::-webkit-scrollbar-thumb{background:${C.border};border-radius:2px;}select option{background:${C.surface};color:${C.text};}input::placeholder,textarea::placeholder{color:${C.muted};}textarea{resize:vertical;}button:disabled{opacity:.4;cursor:not-allowed!important;}a{text-decoration:none;}@media(max-width:700px){.sidebar{width:52px!important;}.sidebar-label{display:none!important;}}`}</style>

      {selectedIOC&&<EnrichmentPanel ioc={selectedIOC} token={token} onClose={()=>setSelectedIOC(null)} C={C} me={me}/>}

      {/* Sidebar */}
      <div className="sidebar" style={{width:200,background:C.surface,borderRight:`1px solid ${C.border}`,display:"flex",flexDirection:"column",flexShrink:0}}>
        <div style={{padding:"14px 12px",borderBottom:`1px solid ${C.border}`}}>
          <div style={{fontSize:15,fontWeight:700,letterSpacing:2,color:C.accentText,marginBottom:10}}>TFII</div>
          <div style={{display:"flex",background:C.surfaceHi,borderRadius:8,padding:2,gap:2}}>
            {[["ioc","IOC","◈"],["cve","CVE","🛡️"]].map(([m,label,icon])=>(
              <button key={m} onClick={()=>switchMode(m)} style={{
                flex:1,padding:"6px 4px",borderRadius:6,border:"none",cursor:"pointer",
                fontSize:11,fontFamily:"inherit",fontWeight:700,
                background:mode===m?C.accent:"transparent",
                color:mode===m?"#fff":C.muted,
                transition:"all .15s",display:"flex",alignItems:"center",
                justifyContent:"center",gap:4,
              }}>
                <span>{icon}</span>{label}
              </button>
            ))}
          </div>
        </div>
        <nav style={{padding:"6px",flex:1,overflowY:"auto"}}>
          {NAV.map(n=>{const active=view===n.id;return(
            <button key={n.id} onClick={()=>setView(n.id)} style={{display:"flex",alignItems:"center",gap:10,width:"100%",padding:"8px 10px",borderRadius:8,marginBottom:2,border:"none",cursor:"pointer",background:active?C.accentDim:"transparent",color:active?C.accentText:C.muted,fontSize:12,fontFamily:"inherit",textAlign:"left",fontWeight:active?700:500,borderLeft:`2px solid ${active?C.accentText:"transparent"}`,transition:"all .1s"}}>
              <span style={{fontSize:14}}>{n.icon}</span><span className="sidebar-label">{n.label}</span>
            </button>
          );})}
        </nav>
        <div style={{padding:"12px 16px",borderTop:`1px solid ${C.border}`}}>
          <div style={{fontSize:12,color:C.accentText,fontWeight:600}}>{me?.username}</div>
          <div style={{fontSize:10,color:C.muted,letterSpacing:.5}}>{me?.role?.toUpperCase()}</div>
        </div>
      </div>

      {/* Main */}
      <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
        {/* Topbar */}
        <div style={{padding:"11px 20px",borderBottom:`1px solid ${C.border}`,background:C.surface,display:"flex",alignItems:"center",justifyContent:"space-between",gap:12,flexShrink:0,flexWrap:"wrap"}}>
          <div style={{fontSize:14,fontWeight:700,color:C.white}}>{NAV.find(n=>n.id===view)?.label||view}</div>
          <GlobalSearch token={token} C={C} onSelect={setSelectedIOC}/>
          <div style={{display:"flex",gap:8,alignItems:"center"}}>
            <NotificationBell token={token} C={C} isAdmin={me?.role==="admin"}/>
            {view==="feed"&&<>
              <button onClick={fetchIOCs} style={{padding:"7px 12px",background:"none",border:`1px solid ${C.border}`,color:C.muted,borderRadius:7,cursor:"pointer",fontSize:13}}>↻</button>
              <button onClick={downloadSTIX} style={{padding:"7px 12px",background:C.accentDim,border:`1px solid ${C.accent}40`,color:C.accentText,borderRadius:7,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600}}>STIX</button>
              <button onClick={()=>{setView("add");setAddResult(null);}} style={{padding:"7px 14px",background:C.accent,border:"none",color:"#fff",borderRadius:7,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:700}}>+ Add</button>
            </>}
          </div>
        </div>

        <div style={{flex:1,overflow:"auto",padding:20}}>
          {view==="dashboard"&&<><Dashboard token={token} C={C}/><CVESummaryStrip token={token} C={C}/></>}
          {view==="cve"&&<CVEDashboard token={token} C={C}/>}
          {view==="map"&&<GeoMap token={token} C={C}/>}
          {view==="intel"&&<IntelNews token={token} C={C}/>}
          {view==="actors"&&<ThreatActors token={token} C={C}/>}
          {view==="osint"&&<OSINTTool token={token} C={C}/>}
          {view==="querygen"&&<QueryGenerator token={token} C={C}/>}
          {view==="public"&&<PublicSearch C={C}/>}
          {view==="settings"&&<SettingsPage themeName={themeName} setThemeName={setThemeName} token={token} onLogout={logout} C={C} me={me}/>}

          {view==="feed"&&(
            <>
              <div style={{display:"flex",gap:8,marginBottom:14,flexWrap:"wrap",alignItems:"center"}}>
                <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Filter feed..."
                  style={{flex:1,minWidth:140,background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"8px 12px",borderRadius:8,fontSize:13,outline:"none",fontFamily:"inherit"}}/>
                {[[["All",...INDUSTRIES],filterIndustry,setFilterIndustry,"Industry"],[["All",...IOC_TYPES],filterType,setFilterType,"Type"],[["All",...TLP_LEVELS],filterTLP,setFilterTLP,"TLP"]].map(([opts,val,setVal,label],idx)=>(
                  <select key={idx} value={val} onChange={e=>setVal(e.target.value)} style={{background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"8px 10px",borderRadius:8,fontSize:12,outline:"none",fontFamily:"inherit"}}>
                    <option value="All">{label}: All</option>{opts.slice(1).map(o=><option key={o}>{o}</option>)}
                  </select>
                ))}
                <select value={filterCampaign} onChange={e=>setFilterCampaign(e.target.value)} style={{background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"8px 10px",borderRadius:8,fontSize:12,outline:"none",fontFamily:"inherit"}}>
                  <option value="All">Campaign: All</option>{campaigns.map(c=><option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
                <label style={{display:"flex",alignItems:"center",gap:5,fontSize:12,color:C.muted,cursor:"pointer"}}><input type="checkbox" checked={filterExpired} onChange={e=>setFilterExpired(e.target.checked)} style={{accentColor:C.accent}}/>Expired</label>
                <label style={{display:"flex",alignItems:"center",gap:5,fontSize:12,color:C.muted,cursor:"pointer"}}><input type="checkbox" checked={filterFP} onChange={e=>setFilterFP(e.target.checked)} style={{accentColor:C.accent}}/>FP</label>
              </div>
              {loading?<div style={{textAlign:"center",padding:60,color:C.muted}}>Loading...</div>:(
                <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,overflow:"hidden",boxShadow:C.shadow}}>
                  <div style={{overflowX:"auto"}}>
                    <table style={{width:"100%",borderCollapse:"collapse",fontSize:13}}>
                      <thead><tr style={{background:C.surfaceHi,borderBottom:`1px solid ${C.border}`}}>{["Type","Indicator","Industry","TLP","Conf","Author","MITRE","Tags",""].map(h=><th key={h} style={{padding:"10px 12px",textAlign:"left",color:C.muted,fontSize:11,fontWeight:700,whiteSpace:"nowrap",letterSpacing:.5}}>{h}</th>)}</tr></thead>
                      <tbody>
                        {filtered.length===0&&<tr><td colSpan={9} style={{padding:48,textAlign:"center",color:C.muted}}>{iocs.length===0?"No IOCs yet":"No matches"}</td></tr>}
                        {filtered.map((ioc,idx)=>{
                          const canDelete=me?.role==="admin"||ioc.created_by===me?.id;
                          return(<tr key={ioc.id} onClick={()=>setSelectedIOC(ioc)} style={{borderBottom:`1px solid ${C.border}20`,cursor:"pointer",background:ioc.false_positive?C.amber+"08":ioc.expired?C.red+"05":idx%2===0?"transparent":C.surfaceHi+"40"}}
                            onMouseEnter={e=>e.currentTarget.style.background=C.surfaceHi} onMouseLeave={e=>e.currentTarget.style.background=ioc.false_positive?C.amber+"08":ioc.expired?C.red+"05":idx%2===0?"transparent":C.surfaceHi+"40"}>
                            <td style={{padding:"9px 12px"}} onClick={e=>e.stopPropagation()}><span style={{fontSize:11,padding:"2px 7px",borderRadius:4,background:C.badge,color:C.accentText,fontWeight:700}}>{ioc.type}</span></td>
                            <td style={{padding:"9px 12px",maxWidth:180,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",color:C.white,fontWeight:500}}>
                              {ioc.value_defanged||ioc.value}
                              {ioc.false_positive&&<span style={{marginLeft:6,fontSize:9,color:C.amber,border:`1px solid ${C.amber}40`,padding:"1px 4px",borderRadius:2,fontWeight:700}}>FP</span>}
                              {ioc.expired&&<span style={{marginLeft:6,fontSize:9,color:C.red,border:`1px solid ${C.red}40`,padding:"1px 4px",borderRadius:2,fontWeight:700}}>EXP</span>}
                            </td>
                            <td style={{padding:"9px 12px",color:C.purple,fontSize:12,fontWeight:500}}>{ioc.industry}</td>
                            <td style={{padding:"9px 12px"}}><TLPBadge level={ioc.tlp}/></td>
                            <td style={{padding:"9px 12px"}}><ConfBar val={ioc.confidence} C={C}/></td>
                            <td style={{padding:"9px 12px",whiteSpace:"nowrap"}}><span style={{fontSize:12,color:ioc.created_by===me?.id?C.accentText:C.muted,fontWeight:ioc.created_by===me?.id?600:400}}>{ioc.author||"?"}{ioc.created_by===me?.id?" ✦":""}</span></td>
                            <td style={{padding:"9px 12px",maxWidth:120}}>{(ioc.mitre_techniques||[]).slice(0,1).map(t=><span key={t} style={{fontSize:10,padding:"1px 5px",borderRadius:3,background:C.purple+"20",color:C.purple,fontWeight:600,whiteSpace:"nowrap",display:"inline-block"}}>{t.split(" - ")[0]}</span>)}{(ioc.mitre_techniques||[]).length>1&&<span style={{fontSize:10,color:C.muted,marginLeft:3}}>+{ioc.mitre_techniques.length-1}</span>}</td>
                            <td style={{padding:"9px 12px",minWidth:80}}><div style={{display:"flex",flexWrap:"wrap"}}>{(ioc.tags||[]).slice(0,2).map(t=><Tag key={t} label={t} C={C}/>)}{(ioc.tags||[]).length>2&&<Tag label={`+${ioc.tags.length-2}`} C={C}/>}</div></td>
                            <td style={{padding:"9px 12px"}} onClick={e=>e.stopPropagation()}>{canDelete&&<button onClick={e=>deleteIOC(ioc.id,e)} style={{background:"none",border:"none",color:C.red,cursor:"pointer",fontSize:16,padding:0,opacity:.6}}>×</button>}</td>
                          </tr>);
                        })}
                      </tbody>
                    </table>
                  </div>
                  <div style={{padding:"8px 14px",borderTop:`1px solid ${C.border}`,fontSize:11,color:C.muted,display:"flex",justifyContent:"space-between"}}>
                    <span>Click any row for enrichment, notes, score history, relationships</span>
                    <span>{filtered.length} of {iocs.length} IOCs · Defanged display</span>
                  </div>
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
