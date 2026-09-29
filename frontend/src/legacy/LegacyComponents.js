// Legacy TFII component library. These are the original, working analyst tools
// (CVE lookup, OSINT, redirect tracer, diff checker, advisory builder, settings,
// health, connectors …). The redesigned shell in ../Root.js renders them inside
// the new layout with a TFII-palette `C` theme object, so their behaviour and
// API contracts are unchanged. New surfaces live under ../pages.
import React, { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { API_BASE } from "../config";
const TLP_COLORS = {
  WHITE:{color:"#9ca3af",bg:"#9ca3af15"},GREEN:{color:"#16a34a",bg:"#16a34a15"},
  AMBER:{color:"#d97706",bg:"#d9770615"},RED:{color:"#dc2626",bg:"#dc262615"},
};
// Any code missing here renders as a globe icon and its bare two-letter code on
// the Geo Map, which is how SA and TW showed up once /stats/geo started
// returning data. Extended to cover the hosting and telecom regions that
// actually appear in this feed.
const COUNTRY_NAMES = {
  US:"United States",CN:"China",RU:"Russia",DE:"Germany",GB:"United Kingdom",
  FR:"France",NL:"Netherlands",UA:"Ukraine",BR:"Brazil",IN:"India",
  KR:"South Korea",JP:"Japan",CA:"Canada",AU:"Australia",IT:"Italy",
  RO:"Romania",TR:"Turkey",IR:"Iran",KP:"North Korea",SG:"Singapore",
  SA:"Saudi Arabia",TW:"Taiwan",VN:"Vietnam",HK:"Hong Kong",AE:"UAE",
  ES:"Spain",PL:"Poland",SE:"Sweden",CH:"Switzerland",ID:"Indonesia",
  TH:"Thailand",PK:"Pakistan",BD:"Bangladesh",NG:"Nigeria",ZA:"South Africa",
  MX:"Mexico",AR:"Argentina",IL:"Israel",EG:"Egypt",MY:"Malaysia",
  PH:"Philippines",BG:"Bulgaria",CZ:"Czechia",FI:"Finland",NO:"Norway",
  DK:"Denmark",AT:"Austria",BE:"Belgium",IE:"Ireland",PT:"Portugal",
  HU:"Hungary",GR:"Greece",LT:"Lithuania",LV:"Latvia",EE:"Estonia",
  MD:"Moldova",RS:"Serbia",KZ:"Kazakhstan",BY:"Belarus",CL:"Chile",
  CO:"Colombia",PE:"Peru",NZ:"New Zealand",SC:"Seychelles",PA:"Panama",
};
const COUNTRY_FLAGS = {
  US:"🇺🇸",CN:"🇨🇳",RU:"🇷🇺",DE:"🇩🇪",GB:"🇬🇧",FR:"🇫🇷",NL:"🇳🇱",UA:"🇺🇦",
  BR:"🇧🇷",IN:"🇮🇳",KR:"🇰🇷",JP:"🇯🇵",CA:"🇨🇦",AU:"🇦🇺",IT:"🇮🇹",
  RO:"🇷🇴",TR:"🇹🇷",IR:"🇮🇷",KP:"🇰🇵",SG:"🇸🇬",
  SA:"🇸🇦",TW:"🇹🇼",VN:"🇻🇳",HK:"🇭🇰",AE:"🇦🇪",
  ES:"🇪🇸",PL:"🇵🇱",SE:"🇸🇪",CH:"🇨🇭",ID:"🇮🇩",
  TH:"🇹🇭",PK:"🇵🇰",BD:"🇧🇩",NG:"🇳🇬",ZA:"🇿🇦",
  MX:"🇲🇽",AR:"🇦🇷",IL:"🇮🇱",EG:"🇪🇬",MY:"🇲🇾",
  PH:"🇵🇭",BG:"🇧🇬",CZ:"🇨🇿",FI:"🇫🇮",NO:"🇳🇴",
  DK:"🇩🇰",AT:"🇦🇹",BE:"🇧🇪",IE:"🇮🇪",PT:"🇵🇹",
  HU:"🇭🇺",GR:"🇬🇷",LT:"🇱🇹",LV:"🇱🇻",EE:"🇪🇪",
  MD:"🇲🇩",RS:"🇷🇸",KZ:"🇰🇿",BY:"🇧🇾",CL:"🇨🇱",
  CO:"🇨🇴",PE:"🇵🇪",NZ:"🇳🇿",SC:"🇸🇨",PA:"🇵🇦",
};

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
    heartbeat:<svg {...s}><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
    send:     <svg {...s}><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>,
    edit:     <svg {...s}><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>,
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
async function api(path,opts={},token=null){
  const headers={"Content-Type":"application/json",...(opts.headers||{})};
  if(token)headers["Authorization"]=`Bearer ${token}`;
  const r=await fetch(`${API_BASE}${path}`,{...opts,headers});
  if(r.status===401){localStorage.removeItem("tf_token");window.location.reload();}
  return r;
}

// ── ATOMS ─────────────────────────────────────────────────────────────────────
function TLPBadge({level}){
  const s=TLP_COLORS[level]??TLP_COLORS.WHITE;
  return <span style={{display:"inline-block",fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,color:s.color,background:s.bg,border:`1px solid ${s.color}40`}}>TLP:{level}</span>;
}
// eslint-disable-next-line no-unused-vars
function Field({label,children,C}){
  return(
    <div style={{marginBottom:16}}>
      <label style={{display:"block",fontSize:12,color:C.muted,marginBottom:6,fontWeight:600}}>{label}</label>
      {children}
    </div>
  );
}
function Inp({value,onChange,type="text",placeholder,C,rows}){
  const base={width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"12px 16px",borderRadius:8,fontSize:14,outline:"none",boxSizing:"border-box",fontFamily:"inherit"};
  if(rows)return <textarea value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} rows={rows} style={{...base,resize:"vertical"}}/>;
  return <input type={type} value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} style={base}/>;
}
function Btn({onClick,disabled,children,variant="primary",C,full,sm}){
  const s={primary:{background:C.accent,color:"#fff",border:"none",boxShadow:C.glow||"none"},ghost:{background:"transparent",color:C.muted,border:`1px solid ${C.border}`},danger:{background:"transparent",color:C.red,border:`1px solid ${C.red}50`},dim:{background:C.accentDim,color:C.accentText,border:`1px solid ${C.accent}40`},success:{background:C.green+"20",color:C.green,border:`1px solid ${C.green}40`}};
  return <button onClick={onClick} disabled={disabled} style={{padding:sm?"6px 12px":"10px 20px",borderRadius:8,cursor:disabled?"not-allowed":"pointer",fontSize:sm?12:14,fontFamily:"inherit",fontWeight:600,width:full?"100%":"auto",opacity:disabled?0.4:1,transition:"all .15s",...(s[variant]||s.primary)}}>{children}</button>;
}
function Card({C,children,style={}}){
  return <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:20,boxShadow:C.shadow,...style}}>{children}</div>;
}
// Some operations legitimately take 5-20s (KEV+EPSS cross-referencing, pulling
// six feeds). Static text over that long is indistinguishable from a hang, so
// count the seconds — a number that moves is the cheapest possible proof that
// the request is still alive.
function SlowLoader({C,message,hint,pad=32}){
  const [secs,setSecs]=useState(0);
  useEffect(()=>{
    const t=setInterval(()=>setSecs(s=>s+1),1000);
    return ()=>clearInterval(t);
  },[]);
  return(
    <div style={{textAlign:"center",padding:pad,color:C.muted}}>
      <div style={{display:"inline-flex",alignItems:"center",gap:8,fontSize:13}}>
        <span style={{width:11,height:11,borderRadius:"50%",flexShrink:0,
          border:`2px solid ${C.accent}`,borderTopColor:"transparent",
          display:"inline-block",animation:"tfspin .8s linear infinite"}}/>
        <span>{message}</span>
        <span style={{fontVariantNumeric:"tabular-nums",opacity:.7,fontSize:12}}>{secs}s</span>
      </div>
      {hint&&secs>=8&&(
        <div style={{fontSize:11,color:C.muted,opacity:.8,marginTop:8}}>{hint}</div>
      )}
    </div>
  );
}
function SevBadge({severity,score,C}){
  const s=String(severity||"").toUpperCase();
  const map={CRITICAL:{bg:C.red+"20",color:C.red},HIGH:{bg:C.amber+"20",color:C.amber},MEDIUM:{bg:(C.blue||C.purple)+"20",color:C.blue||C.purple},LOW:{bg:C.muted+"20",color:C.mutedHi||C.muted}};
  const style=map[s]||{bg:C.muted+"20",color:C.muted};
  return <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,background:style.bg,color:style.color,border:`1px solid ${style.color}40`}}>{s||"?"}{score?` ${score}`:""}</span>;
}
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
                style={{padding:"8px 16px",borderRadius:6,border:"none",cursor:"pointer",
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
          {err&&<div style={{padding:"12px 16px",background:C.red+"10",border:`1px solid ${C.red}30`,
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
              <div style={{marginBottom:12,padding:"12px 16px",borderRadius:8,
                background:result.poc?.available?C.red+"08":C.green+"08",
                border:`1px solid ${result.poc?.available?C.red:C.green}30`,
                display:"flex",alignItems:"center",gap:12}}>
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
                <div style={{display:"flex",gap:8,alignItems:"center",flexShrink:0}}>
                  <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,
                    background:(SEV_COLORS[result.severity]||C.muted)+"20",
                    color:SEV_COLORS[result.severity]||C.muted}}>
                    {result.severity} {result.score}
                  </span>
                </div>
              </div>

              {/* Email subject */}
              {format==="email"&&result.subject&&(
                <div style={{marginBottom:12,padding:"12px 16px",background:C.surfaceHi,
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
                <div style={{marginTop:12,padding:"16px 16px",background:C.red+"08",
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
              <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:6,flexWrap:"wrap"}}>
                <span style={{fontSize:16,fontWeight:800,color:C.accentText,fontFamily:"monospace",
                  letterSpacing:"-0.01em"}}>{d.cve_id}</span>
                {inKev&&<span style={{fontSize:11,padding:"4px 8px",borderRadius:5,fontWeight:700,
                  background:C.red+"20",color:C.red,border:`1px solid ${C.red}40`}}>🚨 CISA KEV</span>}
                {d.patch_available&&<span style={{fontSize:11,padding:"4px 8px",borderRadius:5,fontWeight:700,
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
              <div style={{fontSize:13,color:C.text,lineHeight:1.8,padding:"16px 16px",
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
                gap:12,marginBottom:18}}>
                {/* CVSS */}
                <div style={{padding:"12px 16px",background:C.surfaceHi,
                  border:`1px solid ${score>=9?C.red:score>=7?C.amber:C.border}30`,borderRadius:10}}>
                  <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:6,textTransform:"uppercase"}}>CVSS v{nvd?.cvss?.version||"3.1"}</div>
                  <div style={{fontSize:22,fontWeight:800,color:scoreColor,lineHeight:1}}>{score||"N/A"}</div>
                  <div style={{fontSize:10,color:scoreColor,fontWeight:600,marginTop:2}}>{sevLabel}</div>
                </div>
                {/* EPSS */}
                {epss&&(
                  <div style={{padding:"12px 16px",background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:10}}>
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
                <div style={{padding:"12px 16px",background:inKev?C.red+"08":C.surfaceHi,
                  border:`1px solid ${inKev?C.red+"40":C.border}`,borderRadius:10}}>
                  <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:6,textTransform:"uppercase"}}>CISA KEV</div>
                  <div style={{fontSize:14,fontWeight:700,color:inKev?C.red:C.muted}}>
                    {inKev?"In Catalog":"Not Listed"}
                  </div>
                  {kevDate&&<div style={{fontSize:10,color:C.muted,marginTop:2}}>Added {kevDate}</div>}
                </div>
                {/* CWE */}
                {d.cwe&&(
                  <div style={{padding:"12px 16px",background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:10}}>
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
                <div style={{padding:"16px 16px",background:C.green+"08",
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
                      background:C.green+"10",display:"inline-flex",alignItems:"center",gap:8}}>
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
                      <div key={i} style={{padding:"12px 16px",
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
                  <div style={{padding:"12px 16px",background:C.surfaceHi,borderRadius:8,
                    marginBottom:20,fontFamily:"monospace",fontSize:12,color:C.accentText,
                    wordBreak:"break-all",border:`1px solid ${C.border}`}}>
                    {d.cvss_vector||nvd?.cvss?.vector}
                  </div>
                  {/* Metric grid */}
                  <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",gap:12,marginBottom:20}}>
                    {Object.entries(cvssMetrics).filter(([k])=>CVSS_META[k]).map(([key,val])=>{
                      const meta=CVSS_META[key];
                      const valMeta=meta[val];
                      const color=cvssRiskColor(key,val);
                      const bg=cvssRiskBg(key,val);
                      return(
                        <div key={key} style={{padding:"12px 16px",background:bg,
                          border:`1px solid ${color}40`,borderRadius:10}}>
                          <div style={{fontSize:10,color:C.muted,fontWeight:600,marginBottom:6,
                            textTransform:"uppercase",letterSpacing:"0.05em"}}>
                            {meta.label}
                          </div>
                          <div style={{display:"flex",alignItems:"center",gap:8}}>
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
                    display:"flex",alignItems:"center",gap:8}}>
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
                    <div key={j} style={{display:"flex",alignItems:"center",gap:12,
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
                    <div style={{display:"flex",gap:12,flexWrap:"wrap",marginBottom:8}}>
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
function BulkLookup({token,C}){
  const [input,setInput]=useState("");
  const [results,setResults]=useState(null);
  const [summary,setSummary]=useState(null);
  const [loading,setLoading]=useState(false);
  const [err,setErr]=useState("");
  const [filter,setFilter]=useState("all");
  const [addingId,setAddingId]=useState(null);
  const [addedIds,setAddedIds]=useState({});
  const [selected,setSelected]=useState({});
  const [bulkAdding,setBulkAdding]=useState(false);
  const [bulkMsg,setBulkMsg]=useState("");
  const [uploading,setUploading]=useState(false);
  const fileInputRef=useRef(null);

  const VERDICT_META={
    malicious:    {color:C.red,    bg:C.red+"15",    icon:"🔴", label:"Malicious"},
    suspicious:   {color:C.amber,  bg:C.amber+"15",  icon:"🟠", label:"Suspicious"},
    clean:        {color:C.green,  bg:C.green+"15",  icon:"🟢", label:"Clean"},
    unknown:      {color:C.muted,  bg:C.surfaceHi,   icon:"⚪", label:"Unknown"},
    unrecognized: {color:C.muted,  bg:C.surfaceHi,   icon:"❓", label:"Not Recognized"},
    info:         {color:C.accentText, bg:C.accentDim,icon:"ℹ️", label:"Info"},
  };

  const EXAMPLE = `8.8.8.8
evil[.]com
hxxp://malicious-site[.]com/payload.php
test@phish[.]net
d41d8cd98f00b204e9800998ecf8427e
invoice.pdf.exe`;

  async function runLookup(){
    if(!input.trim()){setErr("Paste at least one indicator.");return;}
    setLoading(true);setErr("");setResults(null);setSummary(null);setAddedIds({});setSelected({});setBulkMsg("");
    try{
      const r=await api("/iocs/bulk-lookup",{method:"POST",body:JSON.stringify({input})},token);
      if(r.ok){const d=await r.json();setResults(d.results);setSummary(d.summary);}
      else{const e=await r.json();setErr(e.detail||"Lookup failed.");}
    }catch{setErr("Cannot reach server.");}
    setLoading(false);
  }

  async function handleFileUpload(e){
    const file=e.target.files[0];
    if(!file)return;
    setUploading(true);setErr("");setResults(null);setSummary(null);setAddedIds({});setSelected({});setBulkMsg("");
    try{
      const fd=new FormData();fd.append("file",file);
      const r=await fetch(`${API_BASE}/iocs/bulk-lookup/file`,{method:"POST",
        headers:{Authorization:`Bearer ${token}`},body:fd});
      if(r.ok){const d=await r.json();setResults(d.results);setSummary(d.summary);
        setInput(`(loaded from file: ${file.name})`);}
      else{const e2=await r.json();setErr(e2.detail||"File upload failed.");}
    }catch{setErr("Cannot reach server.");}
    setUploading(false);
    if(fileInputRef.current) fileInputRef.current.value="";
  }

  async function addToFeed(item, idx){
    setAddingId(idx);
    try{
      const r=await api("/iocs",{method:"POST",body:JSON.stringify({
        type:item.type, value:item.refanged, industry:"General", tlp:"AMBER",
        confidence: item.score||50,
        description:`Added from Bulk Lookup — ${item.reason||""}`.slice(0,500),
        tags:[item.verdict,"bulk-lookup"],
      })},token);
      if(r.ok){const d=await r.json();setAddedIds(p=>({...p,[idx]:d.id}));}
    }catch{}
    setAddingId(null);
  }

  function toggleSelect(idx){
    setSelected(p=>({...p,[idx]:!p[idx]}));
  }
  function selectAll(items){
    const next={};items.forEach((_,i)=>{next[filteredIndices[i]]=true;});setSelected(next);
  }
  function selectNone(){setSelected({});}
  function selectMaliciousSuspicious(){
    const next={};results.forEach((r,i)=>{
      if((r.verdict==="malicious"||r.verdict==="suspicious")&&canAddType(r.type)) next[i]=true;
    });setSelected(next);
  }
  function canAddType(t){
    return ["IPv4","IPv6","Domain","URL","MD5","SHA1","SHA256","Email"].includes(t);
  }

  async function addSelectedToFeed(){
    const idxs=Object.keys(selected).filter(k=>selected[k]);
    if(idxs.length===0)return;
    setBulkAdding(true);setBulkMsg("");
    const items=idxs.map(i=>{
      const r=results[i];
      return {type:r.type, value:r.refanged, confidence:r.score||50,
        description:`Added from Bulk Lookup — ${r.reason||""}`.slice(0,500),
        tags:[r.verdict,"bulk-lookup"], enrichment:r.enrichment};
    });
    try{
      const r=await api("/iocs/bulk-create",{method:"POST",body:JSON.stringify({items})},token);
      if(r.ok){
        const d=await r.json();
        const newAdded={};
        let createdIdx=0;
        idxs.forEach(i=>{
          if(createdIdx<d.created.length){newAdded[i]=d.created[createdIdx].id;createdIdx++;}
        });
        setAddedIds(p=>({...p,...newAdded}));
        setBulkMsg(`✓ Added ${d.created_count} to feed${d.skipped_count?`, ${d.skipped_count} skipped (already exist)`:""}`);
        setSelected({});
      }else{const e=await r.json();setBulkMsg(`✗ ${e.detail||"Failed"}`);}
    }catch{setBulkMsg("✗ Cannot reach server.");}
    setBulkAdding(false);
    setTimeout(()=>setBulkMsg(""),6000);
  }

  function downloadCSV(){
    if(!results||results.length===0)return;
    const headers=["input","refanged","type","verdict","score","reason","country","org","cloud_provider","already_tracked"];
    const rows=results.map(r=>[
      r.input, r.refanged, r.type, r.verdict, r.score||"", (r.reason||"").replace(/"/g,'""'),
      r.geo?.country||"", (r.geo?.org||"").replace(/"/g,'""'), r.geo?.cloud_provider||"",
      r.already_tracked?"yes":"no"
    ]);
    const csv=[headers,...rows].map(row=>row.map(cell=>{
      const s=String(cell);
      return /[",\n]/.test(s) ? `"${s}"` : s;
    }).join(",")).join("\n");
    const blob=new Blob([csv],{type:"text/csv;charset=utf-8;"});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url; a.download=`tfii-bulk-lookup-${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  const filtered = results ? results.filter(r=>filter==="all"||r.verdict===filter) : [];
  const filteredIndices = results ? results.map((r,i)=>i).filter(i=>filter==="all"||results[i].verdict===filter) : [];
  const selectedCount = Object.values(selected).filter(Boolean).length;

  function SummaryPill({label,count,color,active,onClick}){
    return(
      <button onClick={onClick}
        style={{padding:"8px 16px",borderRadius:10,cursor:"pointer",fontFamily:"inherit",
          border:`1px solid ${active?color:C.border}`,
          background:active?color+"15":C.surface,
          display:"flex",alignItems:"center",gap:8,minWidth:90}}>
        <span style={{fontSize:20,fontWeight:800,color:count>0?color:C.muted}}>{count}</span>
        <span style={{fontSize:11,color:active?color:C.muted,fontWeight:600}}>{label}</span>
      </button>
    );
  }

  return(
    <div style={{maxWidth:1000}}>
      {/* Input box */}
      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
        padding:"20px 20px",marginBottom:16,boxShadow:C.shadow}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10,flexWrap:"wrap",gap:8}}>
          <div>
            <div style={{fontSize:14,fontWeight:700,color:C.white||C.textHi,marginBottom:2}}>
              Bulk IOC Validator
            </div>
            <div style={{fontSize:12,color:C.muted}}>
              Paste or upload IPs, domains, URLs, hashes, emails, or filenames — fanged or defanged.
            </div>
          </div>
          <div style={{display:"flex",gap:8}}>
            <button onClick={()=>setInput(EXAMPLE)}
              style={{fontSize:11,padding:"4px 12px",borderRadius:6,background:C.surfaceHi,
                border:`1px solid ${C.border}`,color:C.muted,cursor:"pointer",fontFamily:"inherit"}}>
              Load Example
            </button>
            <input ref={fileInputRef} type="file" accept=".txt,.csv,.log" onChange={handleFileUpload}
              style={{display:"none"}}/>
            <button onClick={()=>fileInputRef.current?.click()} disabled={uploading}
              style={{fontSize:11,padding:"4px 12px",borderRadius:6,background:C.accentDim,
                border:`1px solid ${C.accent}40`,color:C.accentText,cursor:"pointer",fontFamily:"inherit",
                fontWeight:600}}>
              {uploading?"Uploading...":"📁 Upload File"}
            </button>
          </div>
        </div>
        <textarea value={input} onChange={e=>setInput(e.target.value)}
          placeholder={`8.8.8.8\nevil[.]com\nhxxp://bad-site[.]com/payload\ntest@phish[.]net\nd41d8cd98f00b204e9800998ecf8427e`}
          rows={7}
          style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
            color:C.inputText,padding:"12px",borderRadius:8,fontSize:12,outline:"none",
            fontFamily:"'JetBrains Mono','Fira Code',monospace",resize:"vertical",
            lineHeight:1.6,boxSizing:"border-box"}}/>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginTop:10,flexWrap:"wrap",gap:8}}>
          <span style={{fontSize:11,color:C.muted}}>
            Max 60 indicators per lookup. Defanged formats (evil[.]com, hxxp://, user[at]domain) auto-detected.
            Files: .txt, .csv, .log (max 2MB).
          </span>
          <Btn onClick={runLookup} disabled={loading||uploading||!input.trim()} C={C}>
            {loading?"Checking...":"🔍 Run Bulk Lookup"}
          </Btn>
        </div>
      </div>

      {err&&<div style={{padding:"12px 16px",background:C.red+"10",border:`1px solid ${C.red}30`,
        borderRadius:8,color:C.red,fontSize:13,marginBottom:16}}>{err}</div>}

      {(loading||uploading)&&(
        <div style={{textAlign:"center",padding:48,color:C.muted}}>
          <div style={{fontSize:14,fontWeight:600,color:C.white||C.textHi,marginBottom:8}}>
            {uploading?"Reading file and checking indicators...":"Checking indicators against VirusTotal, AbuseIPDB, and URLhaus..."}
          </div>
          <div style={{fontSize:12}}>Resolving owner/org/country and this may take a moment for larger batches</div>
        </div>
      )}

      {summary&&(
        <div style={{display:"flex",gap:8,marginBottom:16,flexWrap:"wrap",alignItems:"center"}}>
          <SummaryPill label="All" count={summary.total} color={C.accentText}
            active={filter==="all"} onClick={()=>setFilter("all")}/>
          <SummaryPill label="Malicious" count={summary.malicious} color={C.red}
            active={filter==="malicious"} onClick={()=>setFilter("malicious")}/>
          <SummaryPill label="Suspicious" count={summary.suspicious} color={C.amber}
            active={filter==="suspicious"} onClick={()=>setFilter("suspicious")}/>
          <SummaryPill label="Clean" count={summary.clean} color={C.green}
            active={filter==="clean"} onClick={()=>setFilter("clean")}/>
          <SummaryPill label="Unknown" count={summary.unknown} color={C.muted}
            active={filter==="unknown"} onClick={()=>setFilter("unknown")}/>
          <button onClick={downloadCSV}
            style={{marginLeft:"auto",fontSize:12,padding:"8px 16px",borderRadius:10,cursor:"pointer",
              background:C.surfaceHi,border:`1px solid ${C.border}`,color:C.text,fontWeight:600,
              fontFamily:"inherit",display:"flex",alignItems:"center",gap:8}}>
            ⬇ Download CSV
          </button>
        </div>
      )}

      {results&&results.length>0&&(
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",
          marginBottom:10,flexWrap:"wrap",gap:8,padding:"12px 16px",background:C.surfaceHi,
          borderRadius:10,border:`1px solid ${C.border}`}}>
          <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
            <span style={{fontSize:11,color:C.muted,fontWeight:600}}>
              {selectedCount>0?`${selectedCount} selected`:"Select indicators to bulk-add"}
            </span>
            <button onClick={()=>selectAll(filtered)}
              style={{fontSize:11,padding:"4px 12px",borderRadius:6,background:C.surface,
                border:`1px solid ${C.border}`,color:C.muted,cursor:"pointer",fontFamily:"inherit"}}>
              Select Filtered
            </button>
            <button onClick={selectMaliciousSuspicious}
              style={{fontSize:11,padding:"4px 12px",borderRadius:6,background:C.surface,
                border:`1px solid ${C.amber}40`,color:C.amber,cursor:"pointer",fontFamily:"inherit",fontWeight:600}}>
              Select Malicious + Suspicious
            </button>
            {selectedCount>0&&(
              <button onClick={selectNone}
                style={{fontSize:11,padding:"4px 12px",borderRadius:6,background:"transparent",
                  border:"none",color:C.muted,cursor:"pointer",fontFamily:"inherit"}}>
                Clear
              </button>
            )}
          </div>
          {selectedCount>0&&(
            <Btn onClick={addSelectedToFeed} disabled={bulkAdding} C={C}>
              {bulkAdding?"Adding...":`+ Add ${selectedCount} to Feed`}
            </Btn>
          )}
        </div>
      )}
      {bulkMsg&&(
        <div style={{marginBottom:12,fontSize:12,fontWeight:600,
          color:bulkMsg.startsWith("✓")?C.green:C.red}}>{bulkMsg}</div>
      )}

      {results&&(
        <div style={{display:"flex",flexDirection:"column",gap:12}}>
          {filtered.length===0&&(
            <div style={{textAlign:"center",padding:32,color:C.muted,background:C.surface,
              border:`1px solid ${C.border}`,borderRadius:12}}>
              No indicators match this filter.
            </div>
          )}
          {results.map((item,idx)=>{
            if(filter!=="all"&&item.verdict!==filter) return null;
            const meta = VERDICT_META[item.verdict] || VERDICT_META.unknown;
            const vt = item.enrichment?.virustotal;
            const ab = item.enrichment?.abuseipdb;
            const uh = item.enrichment?.urlhaus;
            const geo = item.geo;
            const addable = canAddType(item.type);
            return(
              <div key={idx} style={{background:C.surface,border:`1px solid ${
                selected[idx]?C.accent:meta.color+"30"}`,
                borderRadius:12,padding:"14px 18px",boxShadow:C.shadow}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",
                  flexWrap:"wrap",gap:12}}>
                  <div style={{display:"flex",gap:12,flex:1,minWidth:0}}>
                    {addable&&(
                      <input type="checkbox" checked={!!selected[idx]} onChange={()=>toggleSelect(idx)}
                        style={{marginTop:4,accentColor:C.accent,width:15,height:15,flexShrink:0,cursor:"pointer"}}/>
                    )}
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6,flexWrap:"wrap"}}>
                        <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,
                          background:meta.bg,color:meta.color}}>
                          {meta.icon} {meta.label}
                        </span>
                        <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:600,
                          background:C.accentDim,color:C.accentText}}>
                          {item.type}
                        </span>
                        {geo?.country&&(
                          <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:600,
                            background:C.surfaceHi,color:C.text,border:`1px solid ${C.border}`}}>
                            🌍 {geo.country}
                          </span>
                        )}
                        {geo?.cloud_provider&&(
                          <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,
                            background:C.purple+"15",color:C.purple}}>
                            ☁️ {geo.cloud_provider}
                          </span>
                        )}
                        {item.already_tracked&&(
                          <span style={{fontSize:10,padding:"2px 7px",borderRadius:4,
                            background:C.surfaceHi,color:C.muted,fontWeight:600}}>
                            Already tracked
                          </span>
                        )}
                      </div>
                      <div style={{fontSize:13,fontFamily:"monospace",color:C.white||C.textHi,
                        fontWeight:600,marginBottom:4,wordBreak:"break-all"}}>
                        {item.defanged||item.refanged}
                      </div>
                      {item.input!==item.refanged&&(
                        <div style={{fontSize:10,color:C.muted,marginBottom:4}}>
                          Original input: <span style={{fontFamily:"monospace"}}>{item.input}</span>
                        </div>
                      )}
                      {geo?.org&&(
                        <div style={{fontSize:11,color:C.muted,marginBottom:4}}>
                          Owner: <span style={{color:C.text,fontWeight:500}}>{geo.org}</span>
                          {geo.asn&&<span style={{marginLeft:6,color:C.muted}}>({geo.asn})</span>}
                          {geo.resolved_ip&&<span style={{marginLeft:6,color:C.muted}}>→ resolved to {geo.resolved_ip}</span>}
                        </div>
                      )}
                      {item.reason&&(
                        <div style={{fontSize:11,color:C.muted,lineHeight:1.5}}>{item.reason}</div>
                      )}
                    </div>
                  </div>
                  {addable&&(
                    addedIds[idx] ? (
                      <span style={{fontSize:11,color:C.green,fontWeight:600,flexShrink:0,
                        padding:"4px 12px"}}>✓ Added to feed</span>
                    ) : (
                      <button onClick={()=>addToFeed(item,idx)} disabled={addingId===idx}
                        style={{fontSize:11,padding:"4px 12px",borderRadius:6,cursor:"pointer",
                          background:C.accentDim,border:`1px solid ${C.accent}40`,
                          color:C.accentText,fontWeight:600,fontFamily:"inherit",flexShrink:0}}>
                        {addingId===idx?"Adding...":"+ Add to Feed"}
                      </button>
                    )
                  )}
                </div>

                {/* Source breakdown */}
                {(vt||ab||uh)&&(
                  <div style={{display:"flex",gap:8,marginTop:10,flexWrap:"wrap",marginLeft:addable?25:0}}>
                    {vt&&(
                      vt.skipped ? (
                        <span style={{fontSize:10,padding:"4px 8px",borderRadius:5,
                          background:C.surfaceHi,color:C.muted,opacity:0.6}}>
                          VT: no API key configured
                        </span>
                      ) : vt.error ? (
                        <span style={{fontSize:10,padding:"4px 8px",borderRadius:5,
                          background:C.red+"10",color:C.red}}>
                          VT: {vt.error.includes("quota")?"daily quota reached":"error checking"}
                        </span>
                      ) : (
                        <span style={{fontSize:10,padding:"4px 8px",borderRadius:5,
                          background:C.surfaceHi,color:C.muted}}>
                          VT: {vt.malicious!==undefined?`${vt.malicious}/${vt.total} flagged`:vt.found===false?"not found":"checked"}
                        </span>
                      )
                    )}
                    {ab&&(
                      ab.skipped ? (
                        <span style={{fontSize:10,padding:"4px 8px",borderRadius:5,
                          background:C.surfaceHi,color:C.muted,opacity:0.6}}>
                          AbuseIPDB: no API key configured
                        </span>
                      ) : ab.error ? (
                        <span style={{fontSize:10,padding:"4px 8px",borderRadius:5,
                          background:C.red+"10",color:C.red}}>
                          AbuseIPDB: {ab.error.includes("quota")?"daily quota reached":"error checking"}
                        </span>
                      ) : (
                        <span style={{fontSize:10,padding:"4px 8px",borderRadius:5,
                          background:C.surfaceHi,color:C.muted}}>
                          AbuseIPDB: {ab.abuse_score}% confidence
                        </span>
                      )
                    )}
                    {uh&&(
                      uh.skipped ? (
                        <span style={{fontSize:10,padding:"4px 8px",borderRadius:5,
                          background:C.surfaceHi,color:C.muted,opacity:0.6}}>
                          URLhaus: no Auth-Key configured
                        </span>
                      ) : uh.error ? (
                        <span style={{fontSize:10,padding:"4px 8px",borderRadius:5,
                          background:C.red+"10",color:C.red}}>
                          URLhaus: {uh.error.includes("quota")?"daily quota reached":uh.error.includes("Auth-Key")?"invalid Auth-Key":"error checking"}
                        </span>
                      ) : (
                        <span style={{fontSize:10,padding:"4px 8px",borderRadius:5,
                          background:C.surfaceHi,color:C.muted}}>
                          URLhaus: {uh.found?`listed (${uh.threat})`:"not listed"}
                        </span>
                      )
                    )}
                    {item.enrichment?.flags?.length>0&&item.enrichment.flags.map((f,i)=>(
                      <span key={i} style={{fontSize:10,padding:"4px 8px",borderRadius:5,
                        background:C.amber+"15",color:C.amber}}>{f}</span>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}


// ── PUBLIC SEARCH ─────────────────────────────────────────────────────────────
// ── DEMO LOCKED PAGE (explorer role hits a gated feature) ────────────────────
function DemoLockedPage({token,C,featureLabel}){
  const [requestStatus,setRequestStatus]=useState(null); // null | 'pending' | 'approved' | 'denied'
  const [checking,setChecking]=useState(true);
  const [showForm,setShowForm]=useState(false);
  const [email,setEmail]=useState("");
  const [message,setMessage]=useState("");
  const [submitting,setSubmitting]=useState(false);
  const [err,setErr]=useState("");

  useEffect(()=>{
    api("/access-requests/me",{},token).then(r=>r.ok?r.json():null).then(d=>{
      if(d&&d.status) setRequestStatus(d.status);
      setChecking(false);
    }).catch(()=>setChecking(false));
  },[token]);

  async function submit(){
    if(!email.trim()){setErr("Email is required so we can let you know.");return;}
    setSubmitting(true);setErr("");
    const r=await api("/access-requests",{method:"POST",
      body:JSON.stringify({email:email.trim(),message:message.trim()})},token);
    if(r.ok){setRequestStatus("pending");setShowForm(false);}
    else{const e=await r.json();setErr(e.detail||"Could not submit request.");}
    setSubmitting(false);
  }

  return(
    <div style={{maxWidth:560,margin:"60px auto",textAlign:"center"}}>
      <div style={{fontSize:40,marginBottom:16}}>🔒</div>
      <div style={{fontSize:18,fontWeight:700,color:C.white||C.textHi,marginBottom:10}}>
        {featureLabel} is part of the live workspace
      </div>
      <div style={{fontSize:13,color:C.muted,lineHeight:1.7,marginBottom:28}}>
        You're using the TFII demo — CVE Lookup, the KQL/SPL builder, OSINT tools, CVE Wall,
        and Bulk IOC Lookup are fully open for anyone to try. The IOC Feed, CVE Monitor, and
        Campaigns are tied to a real, personal threat-intel workspace, so for now those stay
        invite-only while the server is still small. If you've had a chance to look around and
        find it useful, you're welcome to request full access below.
      </div>

      {checking ? null : requestStatus==="pending" ? (
        <div style={{padding:"16px 20px",background:C.amber+"10",border:`1px solid ${C.amber}30`,
          borderRadius:10,color:C.amber,fontSize:13,fontWeight:600}}>
          ⏳ Your request is in — you'll get an email once it's reviewed.
        </div>
      ) : requestStatus==="denied" ? (
        <div style={{padding:"16px 20px",background:C.surfaceHi,border:`1px solid ${C.border}`,
          borderRadius:10,color:C.muted,fontSize:13}}>
          Your previous request wasn't approved. Feel free to reach out directly if you'd like to discuss it.
        </div>
      ) : showForm ? (
        <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
          padding:"20px 24px",textAlign:"left"}}>
          <Field label="Your Email" C={C}>
            <Inp value={email} onChange={setEmail} placeholder="you@email.com" C={C}/>
          </Field>
          <Field label="Anything you'd like to mention? (optional)" C={C}>
            <textarea value={message} onChange={e=>setMessage(e.target.value)}
              placeholder="What you're hoping to use it for, your background, etc."
              rows={3}
              style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                color:C.inputText,padding:"8px 12px",borderRadius:7,fontSize:13,
                outline:"none",fontFamily:"inherit",resize:"vertical",boxSizing:"border-box"}}/>
          </Field>
          {err&&<div style={{fontSize:12,color:C.red,marginBottom:12}}>{err}</div>}
          <div style={{display:"flex",gap:8}}>
            <Btn onClick={submit} disabled={submitting} C={C}>
              {submitting?"Submitting...":"Submit Request"}
            </Btn>
            <Btn onClick={()=>setShowForm(false)} variant="ghost" C={C}>Cancel</Btn>
          </div>
        </div>
      ) : (
        <Btn onClick={()=>setShowForm(true)} C={C}>Request Full Access</Btn>
      )}
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
      <div style={{display:"flex",gap:12,marginBottom:24}}>
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
            {result.reasons?.length>0&&<div style={{marginBottom:16}}><div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:8,textTransform:"uppercase"}}>Why this verdict</div>{result.reasons.map((r,i)=><div key={i} style={{fontSize:12,color:C.text,marginBottom:4,display:"flex",gap:8}}><span style={{color:C.accentText}}>›</span>{r}</div>)}</div>}
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
      <div style={{display:"flex",alignItems:"center",gap:8}}>
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

        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:4}}>
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
                color:C.inputText,padding:"12px 12px",borderRadius:8,fontSize:14,
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

        {err&&<div style={{fontSize:12,color:C.red,margin:"10px 0",padding:"12px 16px",
          background:C.red+"10",borderRadius:6,border:`1px solid ${C.red}30`}}>{err}</div>}
        {msg&&<div style={{fontSize:12,color:C.green,margin:"10px 0",padding:"12px 16px",
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
              <div style={{display:"flex",gap:16,fontSize:12,flexWrap:"wrap",marginBottom:4}}>
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
function GeoMap({token,C}){
  const [geo,setGeo]=useState(null);
  useEffect(()=>{api("/stats/geo",{},token).then(r=>r.ok?r.json():null).then(d=>{if(d)setGeo(d);});},[token]);
  if(!geo)return <div style={{padding:40,textAlign:"center",color:C.muted}}>Loading geographic data...</div>;
  if(geo.countries.length===0)return <div style={{padding:40,textAlign:"center",color:C.muted}}>No geographic data yet. Add IP-type IOCs to see country breakdown.</div>;
  const max=geo.countries[0]?.count||1;
  return(
    <div>
      <div style={{marginBottom:20,padding:14,background:C.accentDim,border:`1px solid ${C.accent}28`,borderRadius:10,fontSize:13,color:C.accentText}}>
        Geographic origin of IP IOCs, from AbuseIPDB and VirusTotal enrichment.
        {typeof geo.total_ips==="number"&&(
          <span style={{display:"block",marginTop:4,color:C.muted,fontSize:12}}>
            {geo.located} of {geo.total_ips} IP IOCs carry country data
            {geo.unlocated>0&&` — the remaining ${geo.unlocated} came from feeds that supply no geo (mostly ThreatFox), so this is a partial view`}.
          </span>
        )}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(270px,1fr))",gap:12}}>
        {geo.countries.map(c=>{
          const flag=COUNTRY_FLAGS[c.code]||"🌐";const name=COUNTRY_NAMES[c.code]||c.code;const pct=Math.round((c.count/max)*100);
          return(<div key={c.code} style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:10,padding:14,boxShadow:C.shadow}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
              <div style={{display:"flex",alignItems:"center",gap:12}}><span style={{fontSize:20}}>{flag}</span><div><div style={{fontSize:13,fontWeight:600,color:C.white}}>{name}</div><div style={{fontSize:11,color:C.muted}}>{c.code}</div></div></div>
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
      <div style={{display:"flex",gap:12,marginBottom:24}}>
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

      {err&&<div style={{padding:"12px 16px",background:C.red+"10",border:`1px solid ${C.red}30`,borderRadius:8,color:C.red,fontSize:13,marginBottom:16}}>{err}</div>}
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
                    <span style={{fontSize:12,padding:"4px 12px",borderRadius:4,fontWeight:700,
                      background:C.red+"20",color:C.red,border:`1px solid ${C.red}30`}}>
                      🚨 CISA KEV — Added {result.kev_date}
                    </span>
                  )}
                  {result.epss&&(
                    <span style={{fontSize:12,padding:"4px 12px",borderRadius:4,fontWeight:600,
                      background:result.epss.epss>=0.5?C.red+"15":result.epss.epss>=0.1?C.amber+"15":C.accentDim,
                      color:result.epss.epss>=0.5?C.red:result.epss.epss>=0.1?C.amber:C.accentText}}>
                      EPSS {(result.epss.epss*100).toFixed(1)}% · {(result.epss.percentile*100).toFixed(0)}th percentile
                    </span>
                  )}
                  {/* CVSS from NVD */}
                  {result.sources?.find(s=>s.source==="NVD"&&s.cvss)?.cvss&&(()=>{
                    const cvss=result.sources.find(s=>s.source==="NVD").cvss;
                    return(
                      <span style={{fontSize:12,padding:"4px 12px",borderRadius:4,fontWeight:700,
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
                    style={{fontSize:11,padding:"4px 12px",borderRadius:6,background:C.accentDim,
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
              <div style={{fontSize:13,color:C.text,lineHeight:1.7,padding:"12px 16px",
                background:C.surfaceHi,borderRadius:8}}>
                {result.sources.find(s=>s.source==="NVD").description}
              </div>
            )}
          </div>

          {/* Source cards */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(280px,1fr))",
            gap:16,marginBottom:16}}>
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
                      <div key={i} style={{marginBottom:8,padding:"8px 12px",
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
              padding:"20px 20px",boxShadow:C.shadow}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:14,
                textTransform:"uppercase",letterSpacing:"0.06em"}}>
                All References ({result.all_refs.length})
              </div>
              <div style={{display:"grid",gap:8}}>
                {result.all_refs.map((ref,i)=>(
                  <div key={i} style={{display:"flex",alignItems:"flex-start",gap:12,
                    padding:"8px 12px",background:C.surfaceHi,borderRadius:6}}>
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
    }
    setLoading(false);
  }

  const tabs=result?[
    result.data?.dns&&Object.keys(result.data.dns).length>0    ?{id:"dns",  label:"DNS"}  :null,
    result.data?.rdap                                           ?{id:"rdap", label:"WHOIS"} :null,
    result.data?.shodan                                         ?{id:"shodan",label:"Shodan"}:null,
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
            padding:"12px 16px",borderRadius:8,fontSize:14,outline:"none",fontFamily:"inherit"}}/>
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
            <div style={{display:"flex",gap:4,background:C.surfaceHi,borderRadius:10,
              padding:3,width:"fit-content",marginBottom:16}}>
              {tabs.map(t=>(
                <button key={t.id} onClick={()=>setActiveTab(t.id)}
                  style={{padding:"8px 16px",borderRadius:7,border:"none",cursor:"pointer",
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
            borderRadius:12,padding:"20px 20px",boxShadow:C.shadow}}>

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
                    <div style={{display:"flex",flexWrap:"wrap",gap:8}}>
                      {result.data.shodan.ports.map(p=>(
                        <span key={p} style={{fontSize:12,padding:"4px 12px",borderRadius:4,
                          background:C.red+"20",color:C.red,fontFamily:"monospace",fontWeight:700}}>{p}</span>
                      ))}
                    </div>
                  </div>
                )}
                {result.data.shodan.vulns?.length>0&&(
                  <div>
                    <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:8,textTransform:"uppercase"}}>Vulnerabilities</div>
                    <div style={{display:"flex",flexWrap:"wrap",gap:8}}>
                      {result.data.shodan.vulns.map(v=>(
                        <span key={v} style={{fontSize:12,padding:"4px 12px",borderRadius:4,
                          background:C.amber+"20",color:C.amber,fontFamily:"monospace",fontWeight:600}}>{v}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
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

// ── URL DECODER ────────────────────────────────────────────────────────────────
function URLDecoder({C}){
  const [input,setInput]=useState("");
  const [iterations,setIterations]=useState(3);
  const [steps,setSteps]=useState([]);
  const [copied,setCopied]=useState(false);

  function refangUrl(s){
    return s.replace(/hxxps?/gi,m=>m.replace('xx','tt').replace('XX','TT'))
             .replace(/\[\.\]/g,'.').replace(/\[:\]/g,':')
             .replace(/\(dot\)/gi,'.').replace(/\(at\)/gi,'@');
  }

  function decode(){
    if(!input.trim()){setSteps([]);return;}
    const result=[];
    let current=refangUrl(input.trim());
    result.push({step:0,label:"Original (refanged)",value:current});
    for(let i=1;i<=Math.min(iterations,10);i++){
      try{
        const next=decodeURIComponent(current);
        if(next===current){
          result.push({step:i,label:`Step ${i} — no change (fully decoded)`,value:next,done:true});
          break;
        }
        result.push({step:i,label:`Step ${i}`,value:next});
        current=next;
      }catch(e){
        result.push({step:i,label:`Step ${i} — decode error`,value:current,error:true});
        break;
      }
    }
    setSteps(result);
  }

  function copyFinal(){
    const final=steps[steps.length-1]?.value||"";
    navigator.clipboard.writeText(final);
    setCopied(true); setTimeout(()=>setCopied(false),2000);
  }

  return(
    <div style={{maxWidth:800}}>
      <div style={{fontSize:12,color:C.muted,marginBottom:16,lineHeight:1.6}}>
        Decodes URL-encoded strings iteratively — useful for multi-layer encoded malware URLs,
        phishing links, and redirect chains. Handles defanged URLs (hxxps, [.]) automatically.
      </div>
      <div style={{display:"flex",gap:8,marginBottom:12,alignItems:"flex-end",flexWrap:"wrap"}}>
        <div style={{flex:1}}>
          <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4}}>Encoded / Defanged URL</div>
          <textarea value={input} onChange={e=>setInput(e.target.value)}
            placeholder="hxxps://evil[.]com%2Fpayload%2F%252Fnested%252Fpath"
            rows={3}
            style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
              color:C.inputText,padding:"12px 12px",borderRadius:8,fontSize:13,
              outline:"none",fontFamily:"monospace",resize:"vertical",boxSizing:"border-box"}}/>
        </div>
        <div style={{flexShrink:0}}>
          <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4}}>Iterations</div>
          <div style={{display:"flex",gap:8,alignItems:"center"}}>
            <input type="number" min={1} max={10} value={iterations}
              onChange={e=>setIterations(Math.max(1,Math.min(10,parseInt(e.target.value)||1)))}
              style={{width:64,background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                color:C.inputText,padding:"10px 10px",borderRadius:8,fontSize:14,
                outline:"none",fontFamily:"inherit",textAlign:"center"}}/>
            <Btn onClick={decode} C={C}>Decode</Btn>
          </div>
        </div>
      </div>

      {steps.length>0&&(
        <div style={{display:"flex",flexDirection:"column",gap:8}}>
          {steps.map((s,idx)=>(
            <div key={idx} style={{background:C.surface,border:`1px solid ${
              s.done?C.green+"40":s.error?C.red+"40":C.border}`,
              borderRadius:10,padding:"12px 16px"}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:6,alignItems:"center"}}>
                <span style={{fontSize:11,fontWeight:700,
                  color:s.done?C.green:s.error?C.red:C.muted}}>
                  {s.label}
                  {s.done&&" ✓"}{s.error&&" ✗"}
                </span>
                {idx===steps.length-1&&!s.error&&(
                  <button onClick={copyFinal}
                    style={{fontSize:11,padding:"4px 12px",borderRadius:5,cursor:"pointer",
                      background:copied?C.green+"20":C.accentDim,
                      border:`1px solid ${copied?C.green:C.accent}40`,
                      color:copied?C.green:C.accentText,fontFamily:"inherit",fontWeight:600}}>
                    {copied?"Copied!":"Copy final"}
                  </button>
                )}
              </div>
              <div style={{fontSize:12,fontFamily:"monospace",color:C.white||C.textHi,
                wordBreak:"break-all",lineHeight:1.6,background:C.surfaceHi,
                padding:"8px 12px",borderRadius:6}}>
                {s.value||<span style={{color:C.muted,fontStyle:"italic"}}>empty</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// hxxp[:]//evil[.]com — the convention the URL Decoder's refang step reverses.
// Shared by the Safe Link Extractor and the Redirect Tracer.
function defangUrl(s){
  return String(s||"").replace(/^https?(?=:\/\/)/i,m=>m.replace(/t/g,"x").replace(/T/g,"X"))
           .replace(/:/g,'[:]').replace(/\./g,'[.]');
}

// ── LINK-WRAPPER UNWRAPPING ───────────────────────────────────────────────────
// Mail gateways rewrite links so the click routes through them first. During
// triage what matters is the real destination, not the gateway's wrapper.

// Proofpoint URLDefense v2 substitutes - for % and _ for / before encoding.
function ppDecodeV2(t){
  try{ return decodeURIComponent(t.replace(/-/g,"%").replace(/_/g,"/")); }
  catch(e){ return t; }
}

// URLDefense v3 replaces special chars with * and ships them base64'd after the
// ; — a lone * consumes one char, ** followed by a base64 digit is a run.
const B64_ALPHA="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function ppDecodeV3(url,b64){
  if(!url.includes("*")) return url;
  let chars="";
  try{ chars=atob(b64.replace(/-/g,"+").replace(/_/g,"/")); }catch(e){ return url; }
  let i=0;
  return url.replace(/\*\*(.)|\*/g,(m,run)=>{
    if(run!==undefined){
      const n=B64_ALPHA.indexOf(run)+2;
      if(n<2) return m;
      const out=chars.substr(i,n); i+=n; return out;
    }
    return i<chars.length?chars[i++]:m;
  });
}

const REDIRECT_PARAMS=["url","u","q","target","redirect","redirecturl","dest","destination"];

// One unwrap pass. Returns {url,via} on success, {via,opaque:true} when the
// wrapper is known but its token can't be reversed, or null when not wrapped.
function unwrapOnce(raw){
  const s=raw.trim();
  const abs=/^[a-z][a-z0-9+.-]*:\/\//i.test(s)?s:"https://"+s;
  let U; try{ U=new URL(abs); }catch(e){ return null; }
  const host=U.hostname.toLowerCase();

  // Microsoft Defender for Office 365
  if(host.endsWith("safelinks.protection.outlook.com")){
    const t=U.searchParams.get("url");
    if(t) return {url:t,via:"Microsoft SafeLinks"};
  }

  // Proofpoint URLDefense — v3 lives in the path, v1/v2 in the ?u= param
  if(host.endsWith("urldefense.com")||host.endsWith("urldefense.proofpoint.com")){
    const v3=abs.match(/\/v3\/__(.+?)__;([^!]*)!/);
    if(v3) return {url:ppDecodeV3(v3[1],v3[2]),via:"Proofpoint URLDefense v3"};
    const t=U.searchParams.get("u");
    if(t){
      const isV2=U.pathname.includes("/v2/");
      return {url:isV2?ppDecodeV2(t):t,via:`Proofpoint URLDefense${isV2?" v2":""}`};
    }
  }

  // Barracuda LinkProtect
  if(host.endsWith("linkprotect.cudasvc.com")){
    const t=U.searchParams.get("a")||U.searchParams.get("url");
    if(t) return {url:t,via:"Barracuda LinkProtect"};
  }

  // Mimecast hands out an opaque token — the destination isn't in the link
  if(/^protect(-[a-z0-9]+)?\.mimecast\.com$/i.test(host)&&U.pathname.startsWith("/s/"))
    return {via:"Mimecast Attachment Protect",opaque:true};

  // Generic redirector: any ?url=/?u=/?q= holding an absolute URL
  for(const p of REDIRECT_PARAMS){
    const t=U.searchParams.get(p);
    if(t&&/^https?:\/\//i.test(t.trim()))
      return {url:t.trim(),via:host.endsWith("google.com")?"Google redirect":"Redirect parameter"};
  }
  return null;
}

// Wrappers nest — SafeLinks around a Proofpoint link is common. Follow the chain.
function unwrapChain(raw){
  const chain=[]; let cur=raw;
  for(let i=0;i<5;i++){
    const r=unwrapOnce(cur);
    if(!r) break;
    if(r.opaque){ chain.push({via:r.via,opaque:true}); break; }
    if(!r.url||r.url===cur) break;
    chain.push({via:r.via,url:r.url});
    cur=r.url;
  }
  return chain;
}

// ── SAFE LINK EXTRACTOR ───────────────────────────────────────────────────────
function SafeLinkExtractor({C}){
  const [input,setInput]=useState("");
  const [links,setLinks]=useState([]);
  const [uniqueOnly,setUniqueOnly]=useState(true);
  const [defang,setDefangOpt]=useState(true);
  const [unwrap,setUnwrap]=useState(true);
  const [copied,setCopied]=useState(null);

  const URL_REGEX=/(?:https?|ftp|ftps|sftp|ldap|smb):\/\/[^\s<>"')\]},;]+|(?:hxxps?|hxxp):\/\/[^\s<>"')\]},;]+|\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|co|uk|de|fr|ru|cn|tk|top|xyz|info|biz|me|tv|cc|zip|mov|app|dev|ai|sh|gg)\b(?:\/[^\s<>"')\]},;]*)?/g;

  function extract(){
    if(!input.trim()){setLinks([]);return;}
    // HTML source escapes query separators — un-escape so wrapper params survive
    const text=input.replace(/&amp;/g,"&");
    const raw=text.match(URL_REGEX)||[];
    let found=raw.map(u=>u.replace(/[.,;)>\]"']+$/,""));
    if(uniqueOnly) found=[...new Set(found)];
    setLinks(found.map(u=>({raw:u,chain:unwrapChain(u)})));
  }

  // What an analyst actually wants on the clipboard: the final destination.
  function targetOf(item){
    const hops=item.chain.filter(h=>h.url);
    return hops.length?hops[hops.length-1].url:item.raw;
  }

  function copyLink(item,idx){
    const u=unwrap?targetOf(item):item.raw;
    navigator.clipboard.writeText(defang?defangUrl(u):u);
    setCopied(idx); setTimeout(()=>setCopied(null),1500);
  }

  function copyAll(){
    const text=links.map(item=>{
      const u=unwrap?targetOf(item):item.raw;
      return defang?defangUrl(u):u;
    }).join('\n');
    navigator.clipboard.writeText(text);
    setCopied("all"); setTimeout(()=>setCopied(null),1500);
  }

  const displayLinks=links.map(item=>{
    const target=unwrap?targetOf(item):item.raw;
    const hops=unwrap?item.chain:[];
    return {
      item,
      wrapped:hops.length>0,
      via:hops.map(h=>h.via).join(" → "),
      opaque:hops.some(h=>h.opaque),
      original:defang?defangUrl(item.raw):item.raw,
      display:defang?defangUrl(target):target,
    };
  });
  const wrappedCount=displayLinks.filter(l=>l.wrapped).length;

  return(
    <div style={{maxWidth:800}}>
      <div style={{fontSize:12,color:C.muted,marginBottom:16,lineHeight:1.6}}>
        Extracts all URLs from pasted text — emails, documents, logs, HTML source.
        Unwraps mail-gateway rewrites (Microsoft SafeLinks, Proofpoint URLDefense,
        Barracuda) back to the real destination, and outputs them defanged for
        safe sharing and analysis.
      </div>
      <textarea value={input} onChange={e=>setInput(e.target.value)}
        placeholder={"Paste email body, log file, HTML source, or any text here...\n\nAll URLs will be extracted and defanged automatically."}
        rows={7}
        style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
          color:C.inputText,padding:"12px 12px",borderRadius:8,fontSize:12,
          outline:"none",fontFamily:"monospace",resize:"vertical",
          marginBottom:10,boxSizing:"border-box"}}/>
      <div style={{display:"flex",gap:12,alignItems:"center",marginBottom:14,flexWrap:"wrap"}}>
        <Btn onClick={extract} C={C}>Extract Links</Btn>
        <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.muted,cursor:"pointer"}}>
          <input type="checkbox" checked={uniqueOnly} onChange={e=>setUniqueOnly(e.target.checked)}
            style={{accentColor:C.accent}}/>
          Unique only
        </label>
        <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.muted,cursor:"pointer"}}>
          <input type="checkbox" checked={defang} onChange={e=>setDefangOpt(e.target.checked)}
            style={{accentColor:C.accent}}/>
          Output defanged
        </label>
        <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.muted,cursor:"pointer"}}>
          <input type="checkbox" checked={unwrap} onChange={e=>setUnwrap(e.target.checked)}
            style={{accentColor:C.accent}}/>
          Unwrap SafeLinks
        </label>
        {links.length>0&&(
          <button onClick={copyAll}
            style={{marginLeft:"auto",fontSize:11,padding:"4px 12px",borderRadius:6,
              cursor:"pointer",background:copied==="all"?C.green+"20":C.accentDim,
              border:`1px solid ${copied==="all"?C.green:C.accent}40`,
              color:copied==="all"?C.green:C.accentText,fontFamily:"inherit",fontWeight:600}}>
            {copied==="all"?"Copied all!":"Copy all"}
          </button>
        )}
      </div>

      {links.length===0&&input.trim()&&(
        <div style={{textAlign:"center",padding:24,color:C.muted,fontSize:13}}>
          No URLs found. Click Extract Links.
        </div>
      )}

      {displayLinks.length>0&&(
        <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:10,overflow:"hidden"}}>
          <div style={{padding:"12px 16px",borderBottom:`1px solid ${C.border}`,
            fontSize:11,fontWeight:700,color:C.muted,display:"flex",justifyContent:"space-between"}}>
            <span>
              {links.length} link{links.length!==1?"s":""} found
              {wrappedCount>0&&` · ${wrappedCount} unwrapped`}
            </span>
            <span>{defang?"defanged output":"live URLs — handle with care"}</span>
          </div>
          <div style={{maxHeight:360,overflowY:"auto"}}>
            {displayLinks.map((item,idx)=>(
              <div key={idx} style={{display:"flex",alignItems:"center",gap:8,
                padding:"8px 14px",borderBottom:`1px solid ${C.border}20`,
                background:idx%2===0?"transparent":C.surfaceHi+"50"}}>
                <div style={{flex:1,minWidth:0}}>
                  {item.wrapped&&(
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4,flexWrap:"wrap"}}>
                      <span style={{fontSize:9,fontWeight:700,padding:"2px 7px",borderRadius:20,
                        background:item.opaque?C.amber+"15":C.accentDim,
                        border:`1px solid ${item.opaque?C.amber+"40":C.accent+"30"}`,
                        color:item.opaque?C.amber:C.accentText,flexShrink:0}}>
                        {item.via}
                      </span>
                      <code style={{fontSize:9.5,color:C.muted,wordBreak:"break-all",
                        lineHeight:1.4,fontFamily:"monospace",textDecoration:"line-through",
                        opacity:0.7}}>
                        {item.original}
                      </code>
                    </div>
                  )}
                  <code style={{fontSize:11,color:C.white||C.textHi,
                    wordBreak:"break-all",lineHeight:1.5,fontFamily:"monospace",display:"block"}}>
                    {item.display}
                  </code>
                  {item.opaque&&(
                    <div style={{fontSize:10,color:C.amber,marginTop:3}}>
                      Opaque token — destination is not recoverable from the link
                    </div>
                  )}
                </div>
                <button onClick={()=>copyLink(item.item,idx)}
                  style={{fontSize:10,padding:"3px 8px",borderRadius:4,cursor:"pointer",
                    flexShrink:0,background:copied===idx?C.green+"20":C.surfaceHi,
                    border:`1px solid ${copied===idx?C.green:C.border}`,
                    color:copied===idx?C.green:C.muted,fontFamily:"inherit"}}>
                  {copied===idx?"✓":"Copy"}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── USER AGENT PARSER ─────────────────────────────────────────────────────────
function UserAgentParser({C}){
  const [ua,setUa]=useState("");
  const [result,setResult]=useState(null);

  function parseUA(str){
    if(!str.trim()){setResult(null);return;}
    const s=str.trim();
    const r={raw:s,browser:{name:"Unknown",version:""},os:{name:"Unknown",version:""},
      device:"Desktop",engine:"Unknown",bot:false,mobile:false,botName:""};

    // ── Bot detection first ───────────────────────────────────────────────────
    const bots=[
      [/Googlebot\/([^\s;)]+)/i,"Googlebot"],
      [/Bingbot\/([^\s;)]+)/i,"Bingbot"],
      [/Slurp/i,"Yahoo Slurp"],
      [/DuckDuckBot/i,"DuckDuckBot"],
      [/Baiduspider/i,"Baiduspider"],
      [/YandexBot/i,"YandexBot"],
      [/Twitterbot/i,"Twitterbot"],
      [/facebookexternalhit/i,"Facebook External"],
      [/Semrush|AhrefsBot|MJ12bot|DotBot|BLEXBot/i,"SEO Bot"],
      [/python-requests|python-urllib/i,"Python Script"],
      [/curl\/([^\s]+)/i,"curl"],
      [/wget\//i,"wget"],
      [/axios|node-fetch/i,"Node.js Script"],
    ];
    for(const [re,name] of bots){
      if(re.test(s)){r.bot=true;r.botName=name;r.device="Bot"; break;}
    }

    // ── Browser ───────────────────────────────────────────────────────────────
    if(!r.bot){
      const browsers=[
        [/EdgA?\/([^\s]+)/i,"Edge"],
        [/OPR\/([^\s]+)|Opera\/([^\s]+)/i,"Opera"],
        [/SamsungBrowser\/([^\s]+)/i,"Samsung Browser"],
        [/UCBrowser\/([^\s]+)/i,"UC Browser"],
        [/YaBrowser\/([^\s]+)/i,"Yandex Browser"],
        [/CriOS\/([^\s]+)/i,"Chrome (iOS)"],
        [/FxiOS\/([^\s]+)/i,"Firefox (iOS)"],
        [/Version\/([^\s]+).*Safari/i,"Safari"],
        [/Chrome\/([^\s]+)/i,"Chrome"],
        [/Firefox\/([^\s]+)/i,"Firefox"],
        [/MSIE ([^\s;]+)|Trident.*rv:([^\s;)]+)/i,"Internet Explorer"],
      ];
      for(const [re,name] of browsers){
        const m=s.match(re);
        if(m){r.browser.name=name;r.browser.version=m[1]||m[2]||"";break;}
      }
    }

    // ── Engine ────────────────────────────────────────────────────────────────
    if(/AppleWebKit\/([^\s]+)/i.test(s)){
      const m=s.match(/AppleWebKit\/([^\s]+)/i);
      r.engine=`WebKit ${m?m[1]:""}`;
    } else if(/Gecko\/([^\s]+)/i.test(s)){
      r.engine="Gecko";
    } else if(/Trident\/([^\s]+)/i.test(s)){
      r.engine="Trident";
    }

    // ── OS ────────────────────────────────────────────────────────────────────
    const osList=[
      [/Windows NT 10\.0/i,"Windows","10 / 11"],
      [/Windows NT 6\.3/i,"Windows","8.1"],
      [/Windows NT 6\.2/i,"Windows","8"],
      [/Windows NT 6\.1/i,"Windows","7"],
      [/Windows NT 6\.0/i,"Windows","Vista"],
      [/Windows NT 5\.1/i,"Windows","XP"],
      [/Windows Phone ([^\s;)]+)/i,"Windows Phone",""],
      [/Android ([^\s;)]+)/i,"Android",""],
      [/iPhone OS ([^\s;)]+)/i,"iOS",""],
      [/iPad.*OS ([^\s;)]+)/i,"iPadOS",""],
      [/Mac OS X ([^\s;)]+)/i,"macOS",""],
      [/CrOS [^\s]+ ([^\s;)]+)/i,"ChromeOS",""],
      [/Linux/i,"Linux",""],
      [/Ubuntu/i,"Ubuntu",""],
      [/Fedora/i,"Fedora",""],
      [/Debian/i,"Debian",""],
    ];
    for(const [re,name,ver] of osList){
      const m=s.match(re);
      if(m){
        r.os.name=name;
        r.os.version=(m[1]||ver||"").replace(/_/g,'.');
        break;
      }
    }

    // ── Device type ───────────────────────────────────────────────────────────
    if(!r.bot){
      if(/iPad/i.test(s)) r.device="Tablet";
      else if(/iPhone|Android.*Mobile|Mobile.*Android|Windows Phone|BB10|BlackBerry|IEMobile/i.test(s)){
        r.device="Mobile"; r.mobile=true;
      } else if(/Android/i.test(s)) r.device="Tablet";
      else r.device="Desktop";
    }

    setResult(r);
  }

  useEffect(()=>{parseUA(ua);},[ua]);// eslint-disable-line react-hooks/exhaustive-deps

  const Field2=({label,value,mono})=>(
    <div style={{padding:"12px 16px",display:"flex",justifyContent:"space-between",
      alignItems:"center",borderBottom:`1px solid ${C.border}20`}}>
      <span style={{fontSize:11,color:C.muted,fontWeight:600,flexShrink:0,minWidth:120}}>{label}</span>
      <span style={{fontSize:12,color:C.white||C.textHi,fontFamily:mono?"monospace":"inherit",
        textAlign:"right",wordBreak:"break-all"}}>{value||"—"}</span>
    </div>
  );

  const deviceIcon=result?(result.bot?"🤖":result.device==="Mobile"?"📱":result.device==="Tablet"?"📲":"🖥️"):"";

  return(
    <div style={{maxWidth:800}}>
      <div style={{fontSize:12,color:C.muted,marginBottom:16,lineHeight:1.6}}>
        Parse any User-Agent string — identify browser, OS, device type, and engine.
        Useful for log analysis, phishing kit fingerprinting, and access log triage.
      </div>
      <textarea value={ua} onChange={e=>setUa(e.target.value)}
        placeholder={"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        rows={3}
        style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
          color:C.inputText,padding:"12px 12px",borderRadius:8,fontSize:12,
          outline:"none",fontFamily:"monospace",resize:"vertical",
          marginBottom:12,boxSizing:"border-box"}}/>
      <button onClick={()=>setUa(navigator.userAgent)}
        style={{fontSize:11,padding:"4px 12px",borderRadius:6,cursor:"pointer",
          background:C.surfaceHi,border:`1px solid ${C.border}`,color:C.muted,
          fontFamily:"inherit",marginBottom:16}}>
        Use my browser's UA
      </button>

      {result&&(
        <>
          {/* Summary pill row */}
          <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:14}}>
            {[
              [deviceIcon,result.device],
              result.bot?["⚠️","Bot / Crawler"]:null,
              result.browser.name!=="Unknown"?["🌐",`${result.browser.name} ${result.browser.version}`.trim()]:null,
              result.os.name!=="Unknown"?["💻",`${result.os.name} ${result.os.version}`.trim()]:null,
            ].filter(Boolean).map(([icon,label],i)=>(
              <span key={i} style={{fontSize:12,padding:"4px 12px",borderRadius:20,fontWeight:600,
                background:result.bot&&label.includes("Bot")?C.amber+"15":C.accentDim,
                border:`1px solid ${result.bot&&label.includes("Bot")?C.amber+"40":C.accent+"30"}`,
                color:result.bot&&label.includes("Bot")?C.amber:C.accentText}}>
                {icon} {label}
              </span>
            ))}
          </div>

          {/* Detail table */}
          <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:10,overflow:"hidden"}}>
            {result.bot&&<Field2 label="Bot / Crawler" value={result.botName}/>}
            <Field2 label="Browser" value={`${result.browser.name} ${result.browser.version}`.trim()}/>
            <Field2 label="Engine" value={result.engine}/>
            <Field2 label="Operating System" value={`${result.os.name} ${result.os.version}`.trim()}/>
            <Field2 label="Device Type" value={result.device}/>
            <Field2 label="Mobile" value={result.mobile?"Yes":"No"}/>
            <div style={{padding:"12px 16px",borderBottom:`1px solid ${C.border}20`}}>
              <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:6}}>Raw UA String</div>
              <code style={{fontSize:11,color:C.text,fontFamily:"monospace",lineHeight:1.6,
                wordBreak:"break-all",display:"block"}}>{result.raw}</code>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── REDIRECT TRACER ───────────────────────────────────────────────────────────
function RedirectTracer({token,C}){
  const [url,setUrl]=useState("");
  const [ua,setUa]=useState("desktop");
  const [maxHops,setMaxHops]=useState(20);
  const [followMeta,setFollowMeta]=useState(true);
  const [res,setRes]=useState(null);
  const [loading,setLoading]=useState(false);
  const [err,setErr]=useState("");
  const [copied,setCopied]=useState(false);

  const UAS=[
    {id:"desktop",label:"Desktop"},{id:"mobile",label:"Mobile"},
    {id:"bot",label:"Googlebot"},{id:"curl",label:"curl"},
  ];

  async function trace(){
    if(!url.trim())return;
    setLoading(true); setRes(null); setErr("");
    try{
      const r=await api("/tools/trace-redirects",{method:"POST",body:JSON.stringify({
        url:url.trim(),user_agent:ua,max_hops:Number(maxHops)||20,follow_meta:followMeta,
      })},token);
      if(r.ok) setRes(await r.json());
      else{ const d=await r.json().catch(()=>({})); setErr(d.detail||`Request failed (${r.status})`); }
    }catch(e){ setErr(String(e.message||e)); }
    setLoading(false);
  }

  function copyChain(){
    if(!res)return;
    const lines=res.hops.map(h=>`${h.hop}. [${h.status||h.error?"ERR":"?"}${h.status?"":""}] ${defangUrl(h.url)}`+
      (h.redirect_type?`  (${h.redirect_type})`:""));
    navigator.clipboard.writeText(
      `Redirect trace — ${defangUrl(res.start_url)}\n`+
      `Final: ${defangUrl(res.final_url)}\nStop: ${res.stop_reason}\n\n`+lines.join("\n"));
    setCopied(true); setTimeout(()=>setCopied(false),2000);
  }

  const statusColor=h=>{
    if(h.blocked||h.error) return C.red;
    if(h.status>=200&&h.status<300) return C.green;
    if(h.status>=300&&h.status<400) return C.amber;
    if(h.status>=400) return C.red;
    return C.muted;
  };

  return(
    <div style={{maxWidth:900}}>
      <div style={{fontSize:12,color:C.muted,marginBottom:16,lineHeight:1.6}}>
        Follows a link hop by hop and shows what happens at every step — status codes,
        resolved IPs, cookies dropped, TLS state and meta-refresh bounces — so you can see
        where a shortened or gateway-wrapped link actually lands without clicking it.
        Requests run from the server, never your browser.
      </div>

      <div style={{display:"flex",gap:8,marginBottom:10,flexWrap:"wrap",alignItems:"flex-end"}}>
        <div style={{flex:"1 1 380px"}}>
          <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4}}>URL (defanged is fine)</div>
          <input value={url} onChange={e=>setUrl(e.target.value)}
            onKeyDown={e=>e.key==="Enter"&&trace()}
            placeholder="hxxps://bit[.]ly/3xAmPle"
            style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
              color:C.inputText,padding:"12px 12px",borderRadius:8,fontSize:13,
              outline:"none",fontFamily:"monospace",boxSizing:"border-box"}}/>
        </div>
        <div>
          <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4}}>Max hops</div>
          <input type="number" min={1} max={20} value={maxHops}
            onChange={e=>setMaxHops(Math.max(1,Math.min(20,parseInt(e.target.value)||1)))}
            style={{width:64,background:C.inputBg,border:`1px solid ${C.inputBorder}`,
              color:C.inputText,padding:"10px",borderRadius:8,fontSize:14,
              outline:"none",fontFamily:"inherit",textAlign:"center"}}/>
        </div>
        <Btn onClick={trace} disabled={loading} C={C}>{loading?"Tracing…":"Trace"}</Btn>
      </div>

      <div style={{display:"flex",gap:12,alignItems:"center",marginBottom:18,flexWrap:"wrap"}}>
        <span style={{fontSize:11,color:C.muted,fontWeight:600}}>User-Agent</span>
        <div style={{display:"flex",gap:2,background:C.surfaceHi,borderRadius:8,padding:3}}>
          {UAS.map(u=>(
            <button key={u.id} onClick={()=>setUa(u.id)}
              style={{padding:"4px 12px",borderRadius:6,border:"none",cursor:"pointer",
                fontSize:11,fontFamily:"inherit",fontWeight:600,
                background:ua===u.id?C.accent:"transparent",color:ua===u.id?"#fff":C.muted}}>
              {u.label}
            </button>
          ))}
        </div>
        <label style={{display:"flex",alignItems:"center",gap:8,fontSize:12,color:C.muted,cursor:"pointer"}}>
          <input type="checkbox" checked={followMeta} onChange={e=>setFollowMeta(e.target.checked)}
            style={{accentColor:C.accent}}/>
          Follow meta refresh
        </label>
        <span style={{fontSize:10.5,color:C.muted,opacity:.75}}>
          Kits cloak on UA — a link can go somewhere harmless for Googlebot and elsewhere for a phone.
        </span>
      </div>

      {err&&(
        <div style={{background:C.red+"12",border:`1px solid ${C.red}40`,borderRadius:8,
          padding:"12px 16px",fontSize:12,color:C.red,marginBottom:14}}>{err}</div>
      )}

      {res&&(
        <>
          {/* Summary */}
          <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:10,
            padding:"16px 16px",marginBottom:14}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",
              marginBottom:10,flexWrap:"wrap",gap:8}}>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                <span style={{fontSize:12,padding:"4px 12px",borderRadius:20,fontWeight:600,
                  background:C.accentDim,border:`1px solid ${C.accent}30`,color:C.accentText}}>
                  {res.hop_count} hop{res.hop_count!==1?"s":""}
                </span>
                <span style={{fontSize:12,padding:"4px 12px",borderRadius:20,fontWeight:600,
                  background:res.crossed_domains?C.amber+"15":C.surfaceHi,
                  border:`1px solid ${res.crossed_domains?C.amber+"40":C.border}`,
                  color:res.crossed_domains?C.amber:C.muted}}>
                  {res.domains.length} domain{res.domains.length!==1?"s":""}
                </span>
              </div>
              <button onClick={copyChain}
                style={{fontSize:11,padding:"4px 12px",borderRadius:6,cursor:"pointer",
                  background:copied?C.green+"20":C.surfaceHi,
                  border:`1px solid ${copied?C.green:C.border}`,
                  color:copied?C.green:C.muted,fontFamily:"inherit",fontWeight:600}}>
                {copied?"Copied!":"Copy chain"}
              </button>
            </div>
            <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:3}}>Final destination</div>
            <code style={{fontSize:12,color:C.white||C.textHi,fontFamily:"monospace",
              wordBreak:"break-all",lineHeight:1.5,display:"block",marginBottom:8}}>
              {res.final_url}
            </code>
            <div style={{fontSize:11,color:C.muted}}>{res.stop_reason}</div>
          </div>

          {/* Hop timeline */}
          <div style={{display:"flex",flexDirection:"column",gap:8}}>
            {res.hops.map((h,i)=>(
              <div key={i} style={{background:C.surface,
                border:`1px solid ${h.blocked||h.error?C.red+"40":C.border}`,
                borderRadius:10,padding:"12px 16px"}}>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:7,flexWrap:"wrap"}}>
                  <span style={{fontSize:10,fontWeight:700,width:22,height:22,borderRadius:11,
                    background:C.surfaceHi,color:C.muted,display:"inline-flex",
                    alignItems:"center",justifyContent:"center",flexShrink:0}}>{h.hop}</span>
                  <span style={{fontSize:12,fontWeight:700,color:statusColor(h)}}>
                    {h.blocked?"BLOCKED":h.error&&!h.status?"ERROR":`${h.status} ${h.reason||""}`.trim()}
                  </span>
                  {h.redirect_type&&(
                    <span style={{fontSize:10,padding:"2px 8px",borderRadius:20,fontWeight:600,
                      background:h.js_only?C.amber+"15":C.surfaceHi,
                      border:`1px solid ${h.js_only?C.amber+"40":C.border}`,
                      color:h.js_only?C.amber:C.muted}}>{h.redirect_type}</span>
                  )}
                  {h.tls&&h.tls!=="valid"&&(
                    <span style={{fontSize:10,padding:"2px 8px",borderRadius:20,fontWeight:600,
                      background:C.red+"12",border:`1px solid ${C.red}35`,color:C.red}}>{h.tls}</span>
                  )}
                  {typeof h.elapsed_ms==="number"&&(
                    <span style={{fontSize:10,color:C.muted,marginLeft:"auto"}}>{h.elapsed_ms} ms</span>
                  )}
                </div>

                <code style={{fontSize:11.5,color:C.white||C.textHi,fontFamily:"monospace",
                  wordBreak:"break-all",lineHeight:1.55,display:"block",
                  background:C.surfaceHi,padding:"7px 9px",borderRadius:6}}>{h.url}</code>

                {h.error&&(
                  <div style={{fontSize:11,color:C.red,marginTop:6,lineHeight:1.5}}>{h.error}</div>
                )}
                {h.title&&(
                  <div style={{fontSize:11,color:C.muted,marginTop:6}}>
                    <span style={{fontWeight:600}}>Title: </span>{h.title}
                  </div>
                )}

                <div style={{display:"flex",gap:16,flexWrap:"wrap",marginTop:7,fontSize:10.5,color:C.muted}}>
                  {h.ips?.length>0&&<span><b style={{fontWeight:600}}>IP</b> {h.ips.join(", ")}</span>}
                  {h.server&&<span><b style={{fontWeight:600}}>Server</b> {h.server}</span>}
                  {h.content_type&&<span><b style={{fontWeight:600}}>Type</b> {h.content_type.split(";")[0]}</span>}
                </div>

                {h.cookies?.length>0&&(
                  <div style={{marginTop:7,fontSize:10.5,color:C.muted}}>
                    <b style={{fontWeight:600}}>Cookies set</b>{" "}
                    {h.cookies.map((c,ci)=>(
                      <span key={ci} style={{display:"inline-block",marginRight:6,padding:"1px 7px",
                        borderRadius:20,background:C.surfaceHi,border:`1px solid ${C.border}`}}>
                        {c.name}{c.flags.length>0&&<span style={{opacity:.65}}> · {c.flags.join(" ")}</span>}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// ── PERMISSIONS MATRIX ────────────────────────────────────────────────────────
// Each capability is tri-state: inherit from the role preset, or explicitly
// grant/revoke for this one account. Showing the inherited value next to the
// override is what makes "why can this person do that?" answerable at a glance.
function PermissionsPanel({user,token,C,onClose,onChanged}){
  const [cat,setCat]=useState(null);
  const [data,setData]=useState(null);
  const [draft,setDraft]=useState({});
  const [role,setRole]=useState(user.role);
  const [busy,setBusy]=useState(false);
  const [err,setErr]=useState("");
  const [msg,setMsg]=useState("");

  const load=useCallback(async()=>{
    setErr("");
    const [a,b]=await Promise.all([
      api("/admin/capabilities",{},token),
      api(`/admin/users/${user.id}/permissions`,{},token),
    ]);
    if(a.ok) setCat(await a.json());
    if(b.ok){ const d=await b.json(); setData(d); setDraft(d.overrides||{}); setRole(d.user.role); }
    else setErr(`Could not load permissions (${b.status})`);
  },[token,user.id]);
  useEffect(()=>{load();},[load]);

  if(!cat||!data) return <Card C={C} style={{marginTop:16}}><div style={{color:C.muted,fontSize:13}}>Loading permissions…</div></Card>;

  const isRoot=data.is_root_admin;
  const preset=new Set(cat.presets[role]||[]);
  const groups=[...new Set(cat.capabilities.map(c=>c.group))];

  // inherit | grant | revoke
  const stateOf=k=>draft[k]===undefined?"inherit":(draft[k]?"grant":"revoke");
  const effective=k=>{const st=stateOf(k);return st==="inherit"?preset.has(k):st==="grant";};
  const setState=(k,st)=>setDraft(d=>{
    const n={...d};
    if(st==="inherit") delete n[k]; else n[k]=(st==="grant");
    return n;
  });

  const dirty=JSON.stringify(draft)!==JSON.stringify(data.overrides||{})||role!==data.user.role;

  async function save(){
    setBusy(true);setErr("");setMsg("");
    try{
      if(role!==data.user.role){
        const r=await api(`/admin/users/${user.id}/role`,{method:"PATCH",body:JSON.stringify({role})},token);
        if(!r.ok){const d=await r.json().catch(()=>({}));setErr(d.detail||"Role change failed");setBusy(false);return;}
      }
      // Send cleared keys as null so the server drops the override row
      const payload={};
      for(const c of cat.capabilities){
        const was=(data.overrides||{})[c.key], now=draft[c.key];
        if(was!==now) payload[c.key]=(now===undefined?null:now);
      }
      if(Object.keys(payload).length){
        const r=await api(`/admin/users/${user.id}/permissions`,{method:"PUT",body:JSON.stringify({overrides:payload})},token);
        if(!r.ok){const d=await r.json().catch(()=>({}));setErr(d.detail||"Save failed");setBusy(false);return;}
      }
      setMsg("Saved.");await load();onChanged&&onChanged();
    }catch(e){setErr(String(e.message||e));}
    setBusy(false);
  }

  const Seg=({k,val,label,tone})=>{
    const active=stateOf(k)===val;
    const col=tone==="grant"?C.green:tone==="revoke"?C.red:C.muted;
    return(
      <button onClick={()=>setState(k,val)} disabled={isRoot}
        style={{padding:"4px 8px",fontSize:10.5,fontWeight:600,fontFamily:"inherit",
          border:`1px solid ${active?col:C.border}`,borderRadius:5,
          background:active?col+"1a":"transparent",color:active?col:C.muted,
          cursor:isRoot?"not-allowed":"pointer",opacity:isRoot?.5:1}}>
        {label}
      </button>
    );
  };

  return(
    <Card C={C} style={{marginTop:16}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",
        marginBottom:6,flexWrap:"wrap",gap:12}}>
        <div>
          <div style={{fontSize:14,fontWeight:700,color:C.white||C.textHi}}>
            Permissions — {data.user.username}
          </div>
          <div style={{fontSize:11.5,color:C.muted,marginTop:2}}>
            Role sets the starting point; per-account grants and revokes layer on top.
          </div>
        </div>
        <Btn onClick={onClose} variant="ghost" sm C={C}>Close</Btn>
      </div>

      {isRoot&&(
        <div style={{background:C.amber+"12",border:`1px solid ${C.amber}40`,borderRadius:8,
          padding:"9px 13px",fontSize:11.5,color:C.amber,margin:"10px 0"}}>
          This is the owner account. It always holds every permission and cannot be
          restricted or demoted — otherwise a mis-click here could lock everyone out.
        </div>
      )}

      <div style={{display:"flex",alignItems:"center",gap:12,margin:"14px 0",flexWrap:"wrap"}}>
        <span style={{fontSize:11.5,color:C.muted,fontWeight:600}}>Role</span>
        <select value={role} onChange={e=>setRole(e.target.value)} disabled={isRoot}
          style={{background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,
            padding:"8px 12px",borderRadius:6,fontSize:12,fontFamily:"inherit",
            cursor:isRoot?"not-allowed":"pointer"}}>
          {cat.roles.map(r=><option key={r} value={r}>{r}</option>)}
        </select>
        <span style={{fontSize:11,color:C.muted}}>
          preset grants {(cat.presets[role]||[]).length} of {cat.capabilities.length}
        </span>
        {role!==data.user.role&&(
          <span style={{fontSize:10.5,padding:"2px 8px",borderRadius:20,fontWeight:600,
            background:C.amber+"15",border:`1px solid ${C.amber}40`,color:C.amber}}>
            {data.user.role} → {role} (unsaved)
          </span>
        )}
      </div>

      {groups.map(g=>(
        <div key={g} style={{marginBottom:14}}>
          <div style={{fontSize:10,fontWeight:700,letterSpacing:".08em",textTransform:"uppercase",
            color:C.muted,marginBottom:6}}>{g}</div>
          <div style={{display:"flex",flexDirection:"column",gap:8}}>
            {cat.capabilities.filter(c=>c.group===g).map(c=>(
              <div key={c.key} style={{display:"flex",alignItems:"flex-start",gap:12,
                padding:"12px 12px",borderRadius:8,background:C.surfaceHi+"55",
                border:`1px solid ${C.border}`}}>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
                    <span style={{fontSize:12.5,fontWeight:600,color:C.white||C.textHi}}>{c.label}</span>
                    <span style={{fontSize:9.5,padding:"1px 6px",borderRadius:4,fontWeight:700,
                      background:effective(c.key)?C.green+"18":C.red+"14",
                      color:effective(c.key)?C.green:C.red}}>
                      {effective(c.key)?"ALLOWED":"BLOCKED"}
                    </span>
                    {stateOf(c.key)!=="inherit"&&(
                      <span style={{fontSize:9.5,color:C.amber}}>override</span>
                    )}
                  </div>
                  <div style={{fontSize:11,color:C.muted,lineHeight:1.5,marginTop:2}}>{c.description}</div>
                </div>
                <div style={{display:"flex",gap:4,flexShrink:0}}>
                  <Seg k={c.key} val="inherit" tone="muted"
                    label={preset.has(c.key)?"Role ✓":"Role ✕"}/>
                  <Seg k={c.key} val="grant"  tone="grant"  label="Grant"/>
                  <Seg k={c.key} val="revoke" tone="revoke" label="Revoke"/>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}

      {err&&<div style={{fontSize:12,color:C.red,marginBottom:10}}>{err}</div>}
      {msg&&<div style={{fontSize:12,color:C.green,marginBottom:10}}>{msg}</div>}
      <div style={{display:"flex",gap:8,alignItems:"center"}}>
        <Btn onClick={save} disabled={busy||!dirty||isRoot} C={C}>{busy?"Saving…":"Save changes"}</Btn>
        {dirty&&!isRoot&&<Btn onClick={()=>{setDraft(data.overrides||{});setRole(data.user.role);}} variant="ghost" sm C={C}>Discard</Btn>}
        {!dirty&&<span style={{fontSize:11.5,color:C.muted}}>No unsaved changes</span>}
      </div>
    </Card>
  );
}

// ── FILE STORE ────────────────────────────────────────────────────────────────
function fmtBytes(n){
  if(n===0||n==null) return "0 B";
  const u=["B","KB","MB","GB"]; let i=0; let v=Number(n);
  while(v>=1024&&i<u.length-1){v/=1024;i++;}
  return `${v>=10||i===0?Math.round(v):v.toFixed(1)} ${u[i]}`;
}

function FilesPage({token,C}){
  const [files,setFiles]=useState([]);
  const [usage,setUsage]=useState({used:0,quota:0,maxFile:0});
  const [loading,setLoading]=useState(true);
  const [busy,setBusy]=useState("");
  const [err,setErr]=useState("");
  const [drag,setDrag]=useState(false);
  const [copied,setCopied]=useState(null);
  const [renaming,setRenaming]=useState(null);
  const [renameVal,setRenameVal]=useState("");
  const fileInput=useRef(null);

  const load=useCallback(async()=>{
    setLoading(true); setErr("");
    try{
      const r=await api("/files",{},token);
      if(r.ok){
        const d=await r.json();
        setFiles(d.files||[]);
        setUsage({used:d.used_bytes||0,quota:d.quota_bytes||0,maxFile:d.max_file_bytes||0});
      } else setErr(`Could not load files (${r.status})`);
    }catch(e){ setErr(String(e.message||e)); }
    setLoading(false);
  },[token]);

  useEffect(()=>{load();},[load]);

  async function upload(fileList){
    const list=[...(fileList||[])];
    if(!list.length) return;
    setErr("");
    for(const f of list){
      if(usage.maxFile&&f.size>usage.maxFile){
        setErr(`"${f.name}" is ${fmtBytes(f.size)} — over the ${fmtBytes(usage.maxFile)} limit.`);
        continue;
      }
      setBusy(`Uploading ${f.name}…`);
      try{
        const fd=new FormData(); fd.append("file",f);
        // No Content-Type header: the browser must set the multipart boundary.
        const r=await fetch(`${API_BASE}/files/upload`,{
          method:"POST",headers:{Authorization:`Bearer ${token}`},body:fd});
        if(!r.ok){
          const d=await r.json().catch(()=>({}));
          setErr(d.detail||`Upload of "${f.name}" failed (${r.status})`);
        }
      }catch(e){ setErr(String(e.message||e)); }
    }
    setBusy(""); load();
  }

  async function patch(id,body){
    setBusy("Saving…");
    try{
      const r=await api(`/files/${id}`,{method:"PATCH",body:JSON.stringify(body)},token);
      if(!r.ok){ const d=await r.json().catch(()=>({})); setErr(d.detail||`Update failed (${r.status})`); }
    }catch(e){ setErr(String(e.message||e)); }
    setBusy(""); load();
  }

  async function remove(f){
    if(!window.confirm(`Delete "${f.filename}"? This removes the file from disk and cannot be undone.`)) return;
    setBusy("Deleting…");
    try{
      const r=await api(`/files/${f.id}`,{method:"DELETE"},token);
      if(!r.ok){ const d=await r.json().catch(()=>({})); setErr(d.detail||`Delete failed (${r.status})`); }
    }catch(e){ setErr(String(e.message||e)); }
    setBusy(""); load();
  }

  // The authenticated download needs an Authorization header, which a plain
  // <a href> cannot send — fetch it and hand the browser a blob instead.
  async function download(f){
    setBusy(`Downloading ${f.filename}…`);
    try{
      const r=await fetch(`${API_BASE}/files/${f.id}/download`,
        {headers:{Authorization:`Bearer ${token}`}});
      if(!r.ok){ setErr(`Download failed (${r.status})`); setBusy(""); return; }
      const blob=await r.blob();
      const url=URL.createObjectURL(blob);
      const a=document.createElement("a");
      a.href=url; a.download=f.filename; document.body.appendChild(a); a.click();
      a.remove(); URL.revokeObjectURL(url);
    }catch(e){ setErr(String(e.message||e)); }
    setBusy("");
  }

  function shareUrl(f){ return `${API_BASE}/f/${f.share_token}`; }

  function copy(text,key){
    navigator.clipboard.writeText(text);
    setCopied(key); setTimeout(()=>setCopied(null),1800);
  }

  const pct=usage.quota?Math.min(100,(usage.used/usage.quota)*100):0;

  return(
    <div>
      <div style={{fontSize:12,color:C.muted,marginBottom:16,lineHeight:1.6,maxWidth:820}}>
        Private file store for the owner account. Files are served as downloads only —
        never rendered in the browser — so an uploaded page or script cannot run against
        this domain. Share links are unguessable and can be revoked; revoking and
        re-sharing issues a new link, so an old one stays dead.
      </div>

      {/* Drop zone */}
      <div
        onDragOver={e=>{e.preventDefault();setDrag(true);}}
        onDragLeave={()=>setDrag(false)}
        onDrop={e=>{e.preventDefault();setDrag(false);upload(e.dataTransfer.files);}}
        onClick={()=>fileInput.current?.click()}
        style={{border:`2px dashed ${drag?C.accent:C.border}`,borderRadius:12,
          background:drag?C.accentDim:C.surface,padding:"26px 20px",textAlign:"center",
          cursor:"pointer",marginBottom:14,transition:"all .15s"}}>
        <input ref={fileInput} type="file" multiple style={{display:"none"}}
          onChange={e=>{upload(e.target.files);e.target.value="";}}/>
        <div style={{fontSize:13,color:C.white||C.textHi,fontWeight:600,marginBottom:4}}>
          {busy||"Drop files here, or click to choose"}
        </div>
        <div style={{fontSize:11,color:C.muted}}>
          Up to {fmtBytes(usage.maxFile)} per file · {fmtBytes(usage.used)} of {fmtBytes(usage.quota)} used
        </div>
        <div style={{height:4,background:C.surfaceHi,borderRadius:4,marginTop:12,
          maxWidth:420,marginLeft:"auto",marginRight:"auto",overflow:"hidden"}}>
          <div style={{width:`${pct}%`,height:"100%",borderRadius:4,
            background:pct>85?C.red:pct>60?C.amber:C.accent,transition:"width .3s"}}/>
        </div>
      </div>

      {err&&(
        <div style={{background:C.red+"12",border:`1px solid ${C.red}40`,borderRadius:8,
          padding:"12px 16px",fontSize:12,color:C.red,marginBottom:14,
          display:"flex",justifyContent:"space-between",gap:12}}>
          <span>{err}</span>
          <button onClick={()=>setErr("")} style={{background:"none",border:"none",
            color:C.red,cursor:"pointer",fontFamily:"inherit",fontSize:12}}>dismiss</button>
        </div>
      )}

      {loading?(
        <div style={{textAlign:"center",padding:30,color:C.muted,fontSize:13}}>Loading…</div>
      ):files.length===0?(
        <div style={{textAlign:"center",padding:36,color:C.muted,fontSize:13}}>
          No files yet.
        </div>
      ):(
        <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,overflow:"hidden"}}>
          <div style={{padding:"10px 16px",borderBottom:`1px solid ${C.border}`,
            fontSize:11,fontWeight:700,color:C.muted,display:"flex",justifyContent:"space-between"}}>
            <span>{files.length} file{files.length!==1?"s":""}</span>
            <span>{files.filter(f=>f.share_token).length} shared publicly</span>
          </div>
          {files.map((f,idx)=>(
            <div key={f.id} style={{padding:"12px 16px",
              borderBottom:idx<files.length-1?`1px solid ${C.border}40`:"none",
              background:idx%2===0?"transparent":C.surfaceHi+"40"}}>
              <div style={{display:"flex",alignItems:"center",gap:12,flexWrap:"wrap"}}>
                {renaming===f.id?(
                  <>
                    <input value={renameVal} autoFocus
                      onChange={e=>setRenameVal(e.target.value)}
                      onKeyDown={e=>{
                        if(e.key==="Enter"){patch(f.id,{filename:renameVal});setRenaming(null);}
                        if(e.key==="Escape") setRenaming(null);
                      }}
                      style={{flex:"1 1 240px",background:C.inputBg,border:`1px solid ${C.accent}`,
                        color:C.inputText,padding:"5px 9px",borderRadius:6,fontSize:12.5,
                        outline:"none",fontFamily:"inherit"}}/>
                    <Btn sm variant="dim" C={C}
                      onClick={()=>{patch(f.id,{filename:renameVal});setRenaming(null);}}>Save</Btn>
                    <Btn sm variant="ghost" C={C} onClick={()=>setRenaming(null)}>Cancel</Btn>
                  </>
                ):(
                  <>
                    <span style={{flex:"1 1 240px",fontSize:13,color:C.white||C.textHi,
                      fontWeight:600,wordBreak:"break-all"}}>{f.filename}</span>
                    <span style={{fontSize:11,color:C.muted,flexShrink:0}}>{fmtBytes(f.size_bytes)}</span>
                    {f.share_token&&(
                      <span style={{fontSize:9.5,padding:"2px 8px",borderRadius:20,fontWeight:700,
                        background:C.amber+"15",border:`1px solid ${C.amber}40`,color:C.amber}}>
                        PUBLIC · {f.download_count||0} ↓
                      </span>
                    )}
                    <div style={{display:"flex",gap:4,flexShrink:0}}>
                      <Btn sm variant="ghost" C={C} onClick={()=>download(f)}>Download</Btn>
                      <Btn sm variant="ghost" C={C}
                        onClick={()=>{setRenaming(f.id);setRenameVal(f.filename);}}>Rename</Btn>
                      <Btn sm variant={f.share_token?"success":"ghost"} C={C}
                        onClick={()=>patch(f.id,{shared:!f.share_token})}>
                        {f.share_token?"Unshare":"Share"}
                      </Btn>
                      <Btn sm variant="danger" C={C} onClick={()=>remove(f)}>Delete</Btn>
                    </div>
                  </>
                )}
              </div>

              {f.share_token&&(
                <div style={{display:"flex",alignItems:"center",gap:8,marginTop:8}}>
                  <code style={{flex:1,fontSize:10.5,color:C.accentText,fontFamily:"monospace",
                    background:C.surfaceHi,padding:"5px 9px",borderRadius:6,
                    wordBreak:"break-all"}}>{shareUrl(f)}</code>
                  <button onClick={()=>copy(shareUrl(f),f.id)}
                    style={{fontSize:10.5,padding:"4px 12px",borderRadius:6,cursor:"pointer",
                      flexShrink:0,background:copied===f.id?C.green+"20":C.accentDim,
                      border:`1px solid ${copied===f.id?C.green:C.accent}40`,
                      color:copied===f.id?C.green:C.accentText,fontFamily:"inherit",fontWeight:600}}>
                    {copied===f.id?"Copied!":"Copy link"}
                  </button>
                </div>
              )}

              <div style={{display:"flex",gap:16,flexWrap:"wrap",marginTop:6,
                fontSize:10,color:C.muted}}>
                <span>{new Date(f.created_at).toLocaleString()}</span>
                {f.content_type&&<span>{f.content_type}</span>}
                {f.sha256&&(
                  <span style={{cursor:"pointer"}} onClick={()=>copy(f.sha256,f.id+"-h")}
                    title="Click to copy full SHA-256">
                    sha256 {f.sha256.slice(0,16)}…{copied===f.id+"-h"&&" ✓"}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── DIFF ENGINE ───────────────────────────────────────────────────────────────
// Myers O(ND) diff, the same shape of algorithm git uses. Common prefix and
// suffix are trimmed first: for the usual case (two near-identical files) that
// collapses the problem to a handful of lines and keeps the quadratic worst
// case out of reach entirely.
function myersOps(a,b,budget){
  const N=a.length,M=b.length;
  if(N===0&&M===0) return [];
  const max=Math.min(budget===undefined?N+M:budget,N+M);
  const v=new Map([[1,0]]); const trace=[];
  for(let d=0;d<=max;d++){
    trace.push(new Map(v));
    for(let k=-d;k<=d;k+=2){
      const down=(k===-d)||(k!==d&&(v.get(k-1)??-1)<(v.get(k+1)??-1));
      let x=down?(v.get(k+1)??0):(v.get(k-1)??0)+1;
      let y=x-k;
      while(x<N&&y<M&&a[x]===b[y]){x++;y++;}
      v.set(k,x);
      if(x>=N&&y>=M) return diffBacktrack(trace,d,N,M);
    }
  }
  return null; // over budget — caller degrades gracefully
}

function diffBacktrack(trace,D,N,M){
  const ops=[]; let x=N,y=M;
  for(let d=D;d>0;d--){
    const v=trace[d]; const k=x-y;
    const down=(k===-d)||(k!==d&&(v.get(k-1)??-1)<(v.get(k+1)??-1));
    const prevK=down?k+1:k-1;
    const prevX=v.get(prevK)??0; const prevY=prevX-prevK;
    while(x>prevX&&y>prevY){x--;y--;ops.push({t:"eq",a:x,b:y});}
    if(down){y--;ops.push({t:"ins",b:y});}
    else{x--;ops.push({t:"del",a:x});}
  }
  while(x>0&&y>0){x--;y--;ops.push({t:"eq",a:x,b:y});}
  while(y>0){y--;ops.push({t:"ins",b:y});}
  while(x>0){x--;ops.push({t:"del",a:x});}
  return ops.reverse();
}

function diffSequences(a,b,budget){
  let pre=0;
  while(pre<a.length&&pre<b.length&&a[pre]===b[pre]) pre++;
  let suf=0;
  while(suf<a.length-pre&&suf<b.length-pre&&
        a[a.length-1-suf]===b[b.length-1-suf]) suf++;
  const midA=a.slice(pre,a.length-suf), midB=b.slice(pre,b.length-suf);
  let mid=myersOps(midA,midB,budget), degraded=false;
  if(mid===null){
    // Too dissimilar to diff within budget — report a wholesale replace rather
    // than locking up the tab.
    degraded=true; mid=[];
    for(let i=0;i<midA.length;i++) mid.push({t:"del",a:i});
    for(let j=0;j<midB.length;j++) mid.push({t:"ins",b:j});
  }
  const ops=[];
  for(let i=0;i<pre;i++) ops.push({t:"eq",a:i,b:i});
  for(const o of mid) ops.push({t:o.t,
    a:o.a===undefined?undefined:o.a+pre, b:o.b===undefined?undefined:o.b+pre});
  for(let i=0;i<suf;i++) ops.push({t:"eq",a:a.length-suf+i,b:b.length-suf+i});
  return {ops,degraded};
}

// Word-level diff so a changed line shows *what* changed inside it, not just
// that the whole line differs.
function diffWords(aStr,bStr){
  const tok=s=>s.match(/\s+|[^\s]+/g)||[];
  const at=tok(aStr),bt=tok(bStr);
  const {ops}=diffSequences(at,bt,2000);
  const left=[],right=[];
  for(const o of ops){
    if(o.t==="eq"){left.push({s:at[o.a],c:0});right.push({s:bt[o.b],c:0});}
    else if(o.t==="del") left.push({s:at[o.a],c:1});
    else right.push({s:bt[o.b],c:1});
  }
  return {left,right};
}

// ── DIFF CHECKER ──────────────────────────────────────────────────────────────
function DiffChecker({C,token}){
  const [left,setLeft]=useState("");
  const [right,setRight]=useState("");
  const [view,setView]=useState("split");      // split | unified
  const [ignoreWs,setIgnoreWs]=useState(false);
  const [ignoreCase,setIgnoreCase]=useState(false);
  const [collapse,setCollapse]=useState(true);
  const [copied,setCopied]=useState(false);
  const [ran,setRan]=useState(false);
  const [ai,setAi]=useState(null);
  const [aiLoading,setAiLoading]=useState(false);
  const [aiErr,setAiErr]=useState("");
  const [aiContext,setAiContext]=useState("");

  const aLines=left.length?left.replace(/\r\n?/g,"\n").split("\n"):[];
  const bLines=right.length?right.replace(/\r\n?/g,"\n").split("\n"):[];

  const norm=s=>{
    let t=s;
    if(ignoreCase) t=t.toLowerCase();
    if(ignoreWs)   t=t.replace(/\s+/g," ").trim();
    return t;
  };

  const {ops,degraded}=useMemo(
    ()=>diffSequences(aLines.map(norm),bLines.map(norm),4000),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [left,right,ignoreWs,ignoreCase]);

  // Pair each run of deletions with the insertions beside it so a changed line
  // sits opposite its replacement instead of drifting down the page.
  const rows=useMemo(()=>{
    const out=[]; let i=0;
    while(i<ops.length){
      if(ops[i].t==="eq"){
        out.push({type:"eq",aNum:ops[i].a+1,bNum:ops[i].b+1,
                  a:aLines[ops[i].a],b:bLines[ops[i].b]});
        i++; continue;
      }
      const dels=[],inss=[];
      while(i<ops.length&&ops[i].t!=="eq"){
        (ops[i].t==="del"?dels:inss).push(ops[i]); i++;
      }
      for(let j=0;j<Math.max(dels.length,inss.length);j++){
        const d=dels[j],s=inss[j];
        out.push({type:d&&s?"mod":d?"del":"ins",
          aNum:d?d.a+1:null,bNum:s?s.b+1:null,
          a:d?aLines[d.a]:null,b:s?bLines[s.b]:null});
      }
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  },[ops]);

  const stats=useMemo(()=>({
    add:rows.filter(r=>r.type==="ins").length,
    del:rows.filter(r=>r.type==="del").length,
    mod:rows.filter(r=>r.type==="mod").length,
    same:rows.filter(r=>r.type==="eq").length,
  }),[rows]);

  // Collapse long unchanged stretches — on a big file the interesting part is
  // otherwise buried under hundreds of identical lines.
  const display=useMemo(()=>{
    if(!collapse) return rows.map(r=>({r}));
    const out=[]; let i=0; const CTX=3;
    while(i<rows.length){
      if(rows[i].type!=="eq"){ out.push({r:rows[i]}); i++; continue; }
      let j=i; while(j<rows.length&&rows[j].type==="eq") j++;
      const run=j-i;
      if(run>CTX*2+2){
        for(let k=i;k<i+CTX;k++) out.push({r:rows[k]});
        out.push({gap:run-CTX*2});
        for(let k=j-CTX;k<j;k++) out.push({r:rows[k]});
      } else for(let k=i;k<j;k++) out.push({r:rows[k]});
      i=j;
    }
    return out;
  },[rows,collapse]);

  function loadFile(e,setter){
    const f=e.target.files?.[0]; if(!f) return;
    if(f.size>4*1024*1024){ alert("File is larger than 4MB — paste a section instead."); return; }
    const rd=new FileReader();
    rd.onload=ev=>{setter(String(ev.target.result||""));setRan(true);};
    rd.readAsText(f);
    e.target.value="";
  }

  function copyUnified(){
    const out=["--- original","+++ changed"];
    for(const r of rows){
      if(r.type==="eq")       out.push(" "+r.a);
      else if(r.type==="del") out.push("-"+r.a);
      else if(r.type==="ins") out.push("+"+r.b);
      else { out.push("-"+r.a); out.push("+"+r.b); }
    }
    navigator.clipboard.writeText(out.join("\n"));
    setCopied(true); setTimeout(()=>setCopied(false),2000);
  }

  // Only the changed lines plus a little surrounding context are sent for AI
  // explanation — unchanged bulk stays on this machine and stays out of the
  // model's context window.
  function buildAiDiff(){
    const out=[]; const CTX=3; let i=0;
    while(i<rows.length){
      if(rows[i].type==="eq"){
        let j=i; while(j<rows.length&&rows[j].type==="eq") j++;
        const run=j-i;
        if(run>CTX*2){
          for(let k=i;k<i+CTX;k++) out.push(" "+rows[k].a);
          out.push(`@@ ${run-CTX*2} unchanged lines omitted @@`);
          for(let k=j-CTX;k<j;k++) out.push(" "+rows[k].a);
        } else for(let k=i;k<j;k++) out.push(" "+rows[k].a);
        i=j; continue;
      }
      const r=rows[i];
      if(r.type==="del")      out.push("-"+r.a);
      else if(r.type==="ins") out.push("+"+r.b);
      else { out.push("-"+r.a); out.push("+"+r.b); }
      i++;
    }
    return out.join("\n");
  }

  async function explainWithAi(){
    setAiLoading(true); setAi(null); setAiErr("");
    try{
      const r=await api("/diff/explain",{method:"POST",body:JSON.stringify({
        diff:buildAiDiff(),
        context:aiContext.trim(),
        stats:`${stats.add} added, ${stats.del} removed, ${stats.mod} changed, ${stats.same} unchanged`,
      })},token);
      if(r.ok) setAi(await r.json());
      else{ const d=await r.json().catch(()=>({})); setAiErr(d.detail||`Request failed (${r.status})`); }
    }catch(e){ setAiErr(String(e.message||e)); }
    setAiLoading(false);
  }

  function swap(){ const l=left; setLeft(right); setRight(l); setAi(null); setAiErr(""); }
  function clearAll(){ setLeft(""); setRight(""); setRan(false); setAi(null); setAiErr(""); }

  const BG={eq:"transparent",del:C.red+"12",ins:C.green+"12",mod:C.amber+"12"};
  const NUMCOL={width:44,textAlign:"right",padding:"1px 8px 1px 0",color:C.muted,
    fontSize:10.5,userSelect:"none",verticalAlign:"top",fontFamily:"monospace"};
  const CELL={padding:"1px 8px",fontSize:11.5,fontFamily:"monospace",lineHeight:1.6,
    whiteSpace:"pre-wrap",wordBreak:"break-word",verticalAlign:"top"};

  const WordSpan=({parts,kind})=>(
    <>{parts.map((p,i)=>(
      <span key={i} style={p.c?{background:kind==="del"?C.red+"33":C.green+"33",
        borderRadius:2}:undefined}>{p.s}</span>
    ))}</>
  );

  const Pane=({label,val,set,lines})=>(
    <div style={{flex:1,minWidth:260}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
        <span style={{fontSize:11,color:C.muted,fontWeight:600}}>{label}</span>
        <label style={{fontSize:10.5,color:C.accentText,cursor:"pointer"}}>
          <input type="file" onChange={e=>loadFile(e,set)} style={{display:"none"}}/>
          load file
        </label>
      </div>
      <textarea value={val} onChange={e=>{set(e.target.value);setRan(true);}} rows={9}
        placeholder="Paste text, config, IOC list, log…"
        style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
          color:C.inputText,padding:"12px 12px",borderRadius:8,fontSize:12,
          outline:"none",fontFamily:"monospace",resize:"vertical",boxSizing:"border-box"}}/>
      <div style={{fontSize:10,color:C.muted,marginTop:3}}>
        {lines.length} line{lines.length!==1?"s":""}
      </div>
    </div>
  );

  return(
    <div>
      <div style={{fontSize:12,color:C.muted,marginBottom:16,lineHeight:1.6,maxWidth:820}}>
        Line-by-line comparison with word-level highlighting inside changed lines.
        Useful for diffing IOC lists between feed pulls, config or rule changes,
        two versions of a phishing kit, or advisory text. The comparison runs
        entirely in your browser — nothing is uploaded unless you press
        <b style={{color:C.accentText}}> Explain with AI</b>, which sends the
        changed lines to Groq.
      </div>

      <div style={{display:"flex",gap:16,marginBottom:12,flexWrap:"wrap"}}>
        <Pane label="Original" val={left}  set={setLeft}  lines={aLines}/>
        <Pane label="Changed"  val={right} set={setRight} lines={bLines}/>
      </div>

      <div style={{display:"flex",gap:12,alignItems:"center",marginBottom:16,flexWrap:"wrap"}}>
        <div style={{display:"flex",gap:2,background:C.surfaceHi,borderRadius:8,padding:3}}>
          {[["split","Side by side"],["unified","Unified"]].map(([id,lbl])=>(
            <button key={id} onClick={()=>setView(id)}
              style={{padding:"4px 12px",borderRadius:6,border:"none",cursor:"pointer",
                fontSize:11,fontFamily:"inherit",fontWeight:600,
                background:view===id?C.accent:"transparent",color:view===id?"#fff":C.muted}}>
              {lbl}
            </button>
          ))}
        </div>
        {[["Ignore whitespace",ignoreWs,setIgnoreWs],
          ["Ignore case",ignoreCase,setIgnoreCase],
          ["Collapse unchanged",collapse,setCollapse]].map(([lbl,val,set])=>(
          <label key={lbl} style={{display:"flex",alignItems:"center",gap:8,fontSize:12,
            color:C.muted,cursor:"pointer"}}>
            <input type="checkbox" checked={val} onChange={e=>set(e.target.checked)}
              style={{accentColor:C.accent}}/>
            {lbl}
          </label>
        ))}
        <div style={{marginLeft:"auto",display:"flex",gap:8}}>
          <Btn onClick={swap} variant="ghost" sm C={C}>Swap</Btn>
          <Btn onClick={clearAll} variant="ghost" sm C={C}>Clear</Btn>
          <Btn onClick={copyUnified} variant="dim" sm C={C}>{copied?"Copied!":"Copy diff"}</Btn>
        </div>
      </div>

      {degraded&&(
        <div style={{background:C.amber+"12",border:`1px solid ${C.amber}40`,borderRadius:8,
          padding:"12px 16px",fontSize:11.5,color:C.amber,marginBottom:12}}>
          These inputs are too dissimilar to align line by line within the time budget —
          showing them as a wholesale replacement rather than freezing the page.
        </div>
      )}

      {ran&&(aLines.length>0||bLines.length>0)&&(
        <>
          <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap"}}>
            {[[`+${stats.add}`,"added",C.green],[`−${stats.del}`,"removed",C.red],
              [`±${stats.mod}`,"changed",C.amber],[`${stats.same}`,"unchanged",C.muted]].map(([n,l,col],i)=>(
              <span key={i} style={{fontSize:12,padding:"4px 12px",borderRadius:20,fontWeight:600,
                background:col+"15",border:`1px solid ${col}35`,color:col}}>{n} {l}</span>
            ))}
            {stats.add===0&&stats.del===0&&stats.mod===0&&(
              <span style={{fontSize:12,padding:"4px 12px",borderRadius:20,fontWeight:600,
                background:C.green+"15",border:`1px solid ${C.green}35`,color:C.green}}>
                identical
              </span>
            )}
          </div>

          {/* AI explanation — opt-in, because pressing it sends the changed
              lines off this machine. */}
          {(stats.add>0||stats.del>0||stats.mod>0)&&(
            <div style={{marginBottom:14}}>
              <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                <Btn onClick={explainWithAi} disabled={aiLoading} variant="dim" sm C={C}>
                  {aiLoading?"Analysing…":"Explain with AI"}
                </Btn>
                <input value={aiContext} onChange={e=>setAiContext(e.target.value)}
                  placeholder="optional: what is this file? e.g. 'Suricata rules for prod edge'"
                  style={{flex:"1 1 320px",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                    color:C.inputText,padding:"8px 12px",borderRadius:6,fontSize:11.5,
                    outline:"none",fontFamily:"inherit",boxSizing:"border-box"}}/>
              </div>
              <div style={{fontSize:10,color:C.muted,marginTop:5,opacity:.8}}>
                Sends the changed lines (plus 3 lines of context each side) to Groq. Unchanged
                bulk is not sent. Avoid on client-confidential material.
              </div>
            </div>
          )}

          {aiErr&&(
            <div style={{background:C.red+"12",border:`1px solid ${C.red}40`,borderRadius:8,
              padding:"12px 16px",fontSize:11.5,color:C.red,marginBottom:14}}>{aiErr}</div>
          )}

          {ai&&(
            <div style={{background:C.surface,border:`1px solid ${C.accent}35`,borderRadius:10,
              padding:"16px 16px",marginBottom:14}}>
              <div style={{display:"flex",gap:8,alignItems:"center",marginBottom:9,flexWrap:"wrap"}}>
                <span style={{fontSize:11,fontWeight:700,color:C.accentText}}>AI ANALYSIS</span>
                {ai.content_type&&(
                  <span style={{fontSize:10.5,padding:"2px 9px",borderRadius:20,fontWeight:600,
                    background:C.surfaceHi,border:`1px solid ${C.border}`,color:C.muted}}>
                    {ai.content_type}
                  </span>
                )}
                {ai.risk&&(()=>{
                  const col=ai.risk==="high"?C.red:ai.risk==="medium"?C.amber:
                            ai.risk==="low"?C.accent:C.green;
                  return(
                    <span style={{fontSize:10.5,padding:"2px 9px",borderRadius:20,fontWeight:700,
                      background:col+"15",border:`1px solid ${col}40`,color:col}}>
                      risk: {ai.risk}
                    </span>
                  );
                })()}
                {ai.truncated&&(
                  <span style={{fontSize:10.5,padding:"2px 9px",borderRadius:20,fontWeight:600,
                    background:C.amber+"15",border:`1px solid ${C.amber}40`,color:C.amber}}>
                    truncated
                  </span>
                )}
              </div>

              {ai.summary&&(
                <div style={{fontSize:12.5,color:C.white||C.textHi,lineHeight:1.65,marginBottom:8}}>
                  {ai.summary}
                </div>
              )}
              {ai.risk_reason&&(
                <div style={{fontSize:11.5,color:C.muted,lineHeight:1.6,marginBottom:12}}>
                  {ai.risk_reason}
                </div>
              )}

              {ai.changes?.length>0&&(
                <div style={{display:"flex",flexDirection:"column",gap:8,marginBottom:12}}>
                  {ai.changes.map((c,i)=>{
                    const col=c.severity==="high"?C.red:c.severity==="medium"?C.amber:
                              c.severity==="low"?C.accent:C.muted;
                    return(
                      <div key={i} style={{borderLeft:`2px solid ${col}`,paddingLeft:10}}>
                        <div style={{fontSize:12,color:C.white||C.textHi,lineHeight:1.55}}>{c.what}</div>
                        {c.impact&&(
                          <div style={{fontSize:11,color:C.muted,lineHeight:1.5,marginTop:2}}>{c.impact}</div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {ai.watch_for?.length>0&&(
                <div style={{borderTop:`1px solid ${C.border}`,paddingTop:10}}>
                  <div style={{fontSize:10.5,fontWeight:700,color:C.muted,marginBottom:5}}>FOLLOW UP</div>
                  {ai.watch_for.map((w,i)=>(
                    <div key={i} style={{fontSize:11.5,color:C.white||C.textHi,lineHeight:1.6,
                      display:"flex",gap:8}}>
                      <span style={{color:C.accent}}>→</span><span>{w}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:10,
            overflow:"auto",maxHeight:560}}>
            <table style={{width:"100%",borderCollapse:"collapse",tableLayout:"fixed"}}>
              <tbody>
                {display.map((d,i)=>{
                  if(d.gap) return(
                    <tr key={i}><td colSpan={view==="split"?4:2}
                      style={{padding:"4px 12px",fontSize:10.5,color:C.muted,
                        background:C.surfaceHi+"60",textAlign:"center",
                        borderTop:`1px solid ${C.border}`,borderBottom:`1px solid ${C.border}`}}>
                      ⋯ {d.gap} unchanged line{d.gap!==1?"s":""}
                    </td></tr>
                  );
                  const r=d.r;
                  const words=r.type==="mod"?diffWords(r.a,r.b):null;
                  if(view==="split") return(
                    <tr key={i} style={{background:BG[r.type]}}>
                      <td style={NUMCOL}>{r.aNum||""}</td>
                      <td style={{...CELL,width:"50%",color:r.a==null?C.muted:C.white||C.textHi,
                        borderRight:`1px solid ${C.border}`}}>
                        {r.a==null?"":words?<WordSpan parts={words.left} kind="del"/>:r.a}
                      </td>
                      <td style={NUMCOL}>{r.bNum||""}</td>
                      <td style={{...CELL,width:"50%",color:r.b==null?C.muted:C.white||C.textHi}}>
                        {r.b==null?"":words?<WordSpan parts={words.right} kind="ins"/>:r.b}
                      </td>
                    </tr>
                  );
                  // Unified: a modified line becomes a - row then a + row.
                  const uni=[];
                  if(r.type==="eq")       uni.push([" ",r.aNum,r.bNum,r.a,"eq"]);
                  else if(r.type==="del") uni.push(["−",r.aNum,null,r.a,"del"]);
                  else if(r.type==="ins") uni.push(["+",null,r.bNum,r.b,"ins"]);
                  else { uni.push(["−",r.aNum,null,r.a,"del"]); uni.push(["+",null,r.bNum,r.b,"ins"]); }
                  return uni.map((u,ui)=>(
                    <tr key={i+"-"+ui} style={{background:BG[u[4]]}}>
                      <td style={NUMCOL}>{u[1]||u[2]||""}</td>
                      <td style={{...CELL,color:C.white||C.textHi}}>
                        <span style={{color:u[4]==="del"?C.red:u[4]==="ins"?C.green:C.muted,
                          fontWeight:700,marginRight:8}}>{u[0]}</span>
                        {u[4]==="del"&&words?<WordSpan parts={words.left} kind="del"/>
                         :u[4]==="ins"&&words?<WordSpan parts={words.right} kind="ins"/>
                         :u[3]}
                      </td>
                    </tr>
                  ));
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

// ── OSINT + TOOLS WRAPPER ─────────────────────────────────────────────────────
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
              style={{padding:"8px 16px",borderRadius:8,border:"none",cursor:"pointer",
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
                    color:C.inputText,padding:"12px 12px",borderRadius:8,fontSize:13,
                    outline:"none",fontFamily:"inherit",resize:"vertical",boxSizing:"border-box"}}/>
              </Field>
            </div>
            <Field label={`MITRE Tactic (optional)`} C={C}>
              <select value={tacticHint} onChange={e=>setTacticHint(e.target.value)}
                style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                  color:C.inputText,padding:"12px 12px",borderRadius:8,fontSize:13,
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

          {err&&<div style={{padding:"12px 16px",background:C.red+"10",border:`1px solid ${C.red}30`,
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
              <div style={{display:"flex",gap:4,background:C.surfaceHi,borderRadius:10,
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
                <div style={{display:"grid",gridTemplateColumns:"2fr 1fr",gap:16}}>
                  {/* Left: Query */}
                  <div>
                    <div style={{background:C.surface,border:`1px solid ${C.border}`,
                      borderRadius:12,overflow:"hidden",boxShadow:C.shadow}}>
                      {/* Query header */}
                      <div style={{padding:"12px 16px",borderBottom:`1px solid ${C.border}`,
                        display:"flex",justifyContent:"space-between",alignItems:"center",
                        background:C.surfaceHi}}>
                        <div style={{display:"flex",gap:12,alignItems:"center"}}>
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
                          style={{fontSize:11,padding:"4px 12px",borderRadius:6,cursor:"pointer",
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
                        borderRadius:10,padding:"16px 16px",boxShadow:C.shadow}}>
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
                        borderRadius:10,padding:"16px 16px",boxShadow:C.shadow}}>
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
                        borderRadius:10,padding:"16px 16px",boxShadow:C.shadow}}>
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
                        borderRadius:10,padding:"16px 16px",boxShadow:C.shadow}}>
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

          {explainErr&&<div style={{padding:"12px 16px",background:C.red+"10",border:`1px solid ${C.red}30`,
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
                padding:"20px 20px",marginBottom:14,boxShadow:C.shadow}}>
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
                        style={{fontSize:11,padding:"4px 12px",borderRadius:6,fontWeight:600,
                          background:C.purple+"20",color:C.purple,border:`1px solid ${C.purple}30`,
                          textDecoration:"none"}}>
                        {explainResult.mitre.technique}
                      </a>
                    )}
                  </div>
                </div>
                {explainResult.estimated_fidelity&&(
                  <div style={{fontSize:11,color:C.muted,padding:"8px 12px",background:C.surfaceHi,
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
                  <div style={{background:C.surface,border:`1px solid ${C.green}30`,borderRadius:10,padding:"16px 16px"}}>
                    <div style={{fontSize:10,color:C.green,fontWeight:600,marginBottom:8,textTransform:"uppercase"}}>✓ What It Catches</div>
                    {explainResult.what_it_catches.map((w,i)=>(
                      <div key={i} style={{fontSize:11,color:C.text,marginBottom:4,lineHeight:1.5}}>• {w}</div>
                    ))}
                  </div>
                )}
                {explainResult.what_it_misses?.length>0&&(
                  <div style={{background:C.surface,border:`1px solid ${C.amber}30`,borderRadius:10,padding:"16px 16px"}}>
                    <div style={{fontSize:10,color:C.amber,fontWeight:600,marginBottom:8,textTransform:"uppercase"}}>✗ What It Misses</div>
                    {explainResult.what_it_misses.map((w,i)=>(
                      <div key={i} style={{fontSize:11,color:C.text,marginBottom:4,lineHeight:1.5}}>• {w}</div>
                    ))}
                  </div>
                )}
                {explainResult.false_positives?.length>0&&(
                  <div style={{background:C.surface,border:`1px solid ${C.red}20`,borderRadius:10,padding:"16px 16px"}}>
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
                    <div key={i} style={{marginBottom:12,padding:"12px 16px",background:C.surfaceHi,borderRadius:8}}>
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

function ApiKeyModal({token, C, onClose}){
  const [keys,setKeys]=useState({});
  const [saving,setSaving]=useState({});
  const [saved,setSaved]=useState({});
  const [existingKeys,setExistingKeys]=useState({});
  const [status,setStatus]=useState({});      // service -> row from /users/me/api-keys
  const [replacing,setReplacing]=useState({});
  const [quota,setQuota]=useState(null);
  const [checks,setChecks]=useState({});      // service -> {busy} | {status, message, tested, at}

  const SERVICES=[
    {id:"virustotal", name:"VirusTotal",    url:"https://www.virustotal.com/gui/my-apikey",       desc:"Malware & IP reputation",     placeholder:"Enter your VT API key"},
    {id:"abuseipdb",  name:"AbuseIPDB",     url:"https://www.abuseipdb.com/account/api",          desc:"IP abuse confidence scoring",  placeholder:"Enter your AbuseIPDB key"},
    {id:"urlhaus",    name:"URLhaus",       url:"https://auth.abuse.ch/",                          desc:"Malware URL/host database (free Auth-Key required since Jun 2025)", placeholder:"Enter your abuse.ch Auth-Key"},
    {id:"groq",       name:"Groq",          url:"https://console.groq.com/keys",                  desc:"SPL/KQL query generation",     placeholder:"gsk_xxxxxxxxxxxx"},
    {id:"shodan",     name:"Shodan",        url:"https://account.shodan.io/",                     desc:"Port scan & host lookup",      placeholder:"Enter your Shodan key"},
    {id:"nvd",        name:"NVD",           url:"https://nvd.nist.gov/developers/request-an-api-key","desc":"CVE database (higher rate limit)","placeholder":"Enter your NVD key"},
    {id:"otx",        name:"AlienVault OTX",url:"https://otx.alienvault.com/settings",            desc:"Threat pulses with adversary and malware context (IOC feed)", placeholder:"Enter your OTX key"},
  ];

  function loadStatus(){
    api("/users/me/api-keys",{},token).then(r=>r.ok?r.json():null).then(d=>{
      if(d){
        const existing={},st={};
        d.forEach(k=>{ st[k.service]=k; if(k.has_key) existing[k.service]=true; });
        setExistingKeys(existing); setStatus(st);
        window.dispatchEvent(new CustomEvent("tfii:keys-changed"));
      }
    }).catch(()=>{});
  }
  useEffect(()=>{
    loadStatus();
    api("/users/me/quota",{},token).then(r=>r.ok?r.json():null).then(q=>{if(q)setQuota(q);});
  },[token]); // eslint-disable-line react-hooks/exhaustive-deps

  async function saveKey(svc){
    const k=keys[svc]?.trim();
    if(!k)return;
    setSaving(p=>({...p,[svc]:true}));
    const r=await api(`/users/me/api-keys/${svc}`,{method:"POST",body:JSON.stringify({api_key:k})},token);
    if(r.ok){setSaved(p=>({...p,[svc]:true}));setKeys(p=>({...p,[svc]:""}));setReplacing(p=>({...p,[svc]:false}));loadStatus();}
    setSaving(p=>({...p,[svc]:false}));
  }
  // Ask the provider whether the key works: the pasted one if there is one, otherwise the saved one.
  async function testKey(svc){
    const pasted=(keys[svc]||"").trim();
    setChecks(p=>({...p,[svc]:{busy:true}}));
    let res;
    try{
      const r=await api(`/users/me/api-keys/${svc}/test`,{method:"POST",body:JSON.stringify(pasted?{api_key:pasted}:{})},token);
      const d=await r.json().catch(()=>({}));
      res=r.ok?{status:d.status,message:d.message,tested:d.tested,at:d.checked_at}
             :{status:"unexpected",message:typeof d.detail==="string"?d.detail:"The check could not be run.",tested:pasted?"pasted":"saved"};
    }catch(e){ res={status:"unreachable",message:"Could not reach the server.",tested:pasted?"pasted":"saved"}; }
    setChecks(p=>({...p,[svc]:res}));
  }
  async function removeKey(svc){
    if(!window.confirm("Remove your saved key for this service?"))return;
    const r=await api(`/users/me/api-keys/${svc}`,{method:"DELETE"},token);
    if(r.ok){setSaved(p=>({...p,[svc]:false}));loadStatus();}
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
            <div style={{padding:"12px 16px",background:C.amber+"15",border:`1px solid ${C.amber}40`,
              borderRadius:8,fontSize:12,color:C.amber,marginBottom:16}}>
              ⚠ You're running low on free daily checks. Add your API keys to continue without limits.
            </div>
          )}
        </div>

        {/* Service list */}
        <div style={{padding:"0 24px"}}>
          {SERVICES.map(svc=>{
            const st=status[svc.id]||{};
            const alreadySaved = !!(st.has_key || saved[svc.id] || existingKeys[svc.id]);
            const showInput = !alreadySaved || replacing[svc.id];
            const platform = st.source==="platform";
            const chip = alreadySaved
              ? {t:"✓ Your key is saved"+(st.masked?` · ${st.masked}`:""), c:C.green}
              : platform ? {t:"Platform key in use"+(st.quota_total?` · ${st.quota_remaining}/${st.quota_total} free today`:""), c:C.accentText}
              : {t:"No key set", c:C.muted};
            return(
            <div key={svc.id} style={{marginBottom:16,padding:14,background:C.surfaceHi,
              border:`1px solid ${alreadySaved?C.green:C.border}`,borderRadius:10}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
                <div>
                  <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
                    <span style={{fontSize:13,fontWeight:700,color:C.white||C.textHi}}>{svc.name}</span>
                    <span data-testid={`key-status-${svc.id}`} style={{fontSize:11,color:chip.c,fontWeight:700}}>{chip.t}</span>
                  </div>
                  <div style={{fontSize:11,color:C.muted,marginTop:2}}>{svc.desc}</div>
                  {alreadySaved&&st.updated_at&&<div style={{fontSize:10,color:C.muted,marginTop:2}}>Updated {String(st.updated_at).slice(0,10)}</div>}
                </div>
                <div style={{display:"flex",gap:10,alignItems:"center",marginLeft:8,whiteSpace:"nowrap"}}>
                  {alreadySaved&&!replacing[svc.id]&&<>
                    <button onClick={()=>testKey(svc.id)} disabled={checks[svc.id]?.busy} data-testid={`key-test-${svc.id}`} style={{background:"none",border:"none",color:C.accentText,cursor:"pointer",fontSize:11,fontWeight:600,fontFamily:"inherit",opacity:checks[svc.id]?.busy?0.5:1}}>{checks[svc.id]?.busy?"Testing…":"Test key"}</button>
                    <button onClick={()=>setReplacing(p=>({...p,[svc.id]:true}))} style={{background:"none",border:"none",color:C.accentText,cursor:"pointer",fontSize:11,fontWeight:600,fontFamily:"inherit"}}>Replace</button>
                    <button onClick={()=>removeKey(svc.id)} style={{background:"none",border:"none",color:C.red,cursor:"pointer",fontSize:11,fontWeight:600,fontFamily:"inherit"}}>Remove</button>
                  </>}
                  {!alreadySaved&&(
                    <a href={svc.url} target="_blank" rel="noreferrer" style={{fontSize:11,color:C.accentText,fontWeight:600}}>Get key →</a>
                  )}
                </div>
              </div>
              {showInput&&(
                <div style={{display:"flex",gap:8,marginTop:8}}>
                  <input type="password" autoComplete="off" value={keys[svc.id]||""} onChange={e=>{const v=e.target.value;setKeys(p=>({...p,[svc.id]:v}));setChecks(p=>(p[svc.id]?{...p,[svc.id]:null}:p));}}
                    onKeyDown={e=>{if(e.key==="Enter")saveKey(svc.id);}}
                    placeholder={alreadySaved?"Paste the new key to replace it":svc.placeholder}
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
                  <button onClick={()=>testKey(svc.id)} data-testid={`key-test-${svc.id}`}
                    disabled={checks[svc.id]?.busy||!keys[svc.id]?.trim()}
                    title="Check with the provider that this key works, without saving it"
                    style={{padding:"8px 12px",background:"none",border:`1px solid ${C.border}`,color:C.accentText,
                      borderRadius:7,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600,
                      opacity:checks[svc.id]?.busy||!keys[svc.id]?.trim()?0.4:1}}>
                    {checks[svc.id]?.busy?"Testing…":"Test"}
                  </button>
                  {replacing[svc.id]&&<button onClick={()=>setReplacing(p=>({...p,[svc.id]:false}))} style={{padding:"8px 10px",background:"none",border:`1px solid ${C.border}`,color:C.muted,borderRadius:7,cursor:"pointer",fontSize:12,fontFamily:"inherit"}}>Cancel</button>}
                </div>
              )}
              {checks[svc.id]&&!checks[svc.id].busy&&(()=>{
                const ck=checks[svc.id];
                const col=ck.status==="valid"?C.green:ck.status==="invalid"?C.red:C.amber;
                const icon=ck.status==="valid"?"✓":ck.status==="invalid"?"✕":"!";
                return <div role="status" data-testid={`key-check-${svc.id}`} style={{marginTop:8,fontSize:11.5,color:col,fontWeight:600,lineHeight:1.5}}>
                  {icon} {ck.status==="valid"?"Key works":ck.status==="invalid"?"Key rejected":"Could not confirm"}
                  <span style={{fontWeight:400,color:C.muted}}> — {ck.message}{ck.tested==="pasted"?" (not saved yet)":""}</span>
                </div>;
              })()}
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
// ── CLIENT ADVISORY BUILDER ───────────────────────────────────────────────────

function NoteCard({note,onEdit,onTogglePin,onArchive,onDelete,onToggleCheck,onTagFilter,C}){
  const ns=getNoteStyle(note.color,C);
  const checklist=(note.checklist||[]);
  const done=checklist.filter(i=>i.checked).length;
  return(
    <div onClick={()=>onEdit(note)}
      style={{...ns, borderRadius:12, padding:"16px 16px",
        cursor:"pointer", position:"relative",
        transition:"box-shadow 0.15s",
        breakInside:"avoid", marginBottom:12}}>
      {/* Pin icon top-right */}
      <div style={{position:"absolute",top:8,right:8,display:"flex",gap:4}}>
        <button onClick={e=>onTogglePin(note,e)}
          title={note.pinned?"Unpin":"Pin"}
          style={{background:"none",border:"none",cursor:"pointer",
            fontSize:14,opacity:note.pinned?1:0.3,padding:2,
            color:note.color==="default"?C.white||C.textHi:"#fff",
            lineHeight:1}}>📌</button>
      </div>
      {note.title&&<div style={{fontSize:13,fontWeight:700,marginBottom:6,paddingRight:28,
        color:note.color==="default"?C.white||C.textHi:"#fff",lineHeight:1.3}}>
        {note.title}
      </div>}
      {note.note_type==="text"&&note.content&&(
        <div style={{fontSize:12,color:note.color==="default"?C.muted:"rgba(255,255,255,0.75)",
          lineHeight:1.6,whiteSpace:"pre-wrap",
          overflow:"hidden",display:"-webkit-box",WebkitLineClamp:8,
          WebkitBoxOrient:"vertical"}}>
          {note.content}
        </div>
      )}
      {note.note_type==="checklist"&&checklist.length>0&&(
        <div>
          {checklist.slice(0,8).map((item,idx)=>(
            <div key={idx} onClick={e=>{e.stopPropagation();onToggleCheck(note,idx);}}
              style={{display:"flex",alignItems:"center",gap:8,marginBottom:4,cursor:"pointer"}}>
              <input type="checkbox" checked={item.checked} readOnly
                style={{accentColor:note.color==="default"?C.accent:"#fff",
                  width:14,height:14,flexShrink:0}}/>
              <span style={{fontSize:12,
                color:note.color==="default"?C.text:"#fff",
                textDecoration:item.checked?"line-through":"none",
                opacity:item.checked?0.5:1,
                lineHeight:1.4}}>
                {item.text||<span style={{opacity:0.3}}>Empty item</span>}
              </span>
            </div>
          ))}
          {checklist.length>8&&(
            <div style={{fontSize:11,opacity:0.6,
              color:note.color==="default"?C.muted:"rgba(255,255,255,0.6)",marginTop:4}}>
              +{checklist.length-8} more items
            </div>
          )}
          {checklist.length>0&&(
            <div style={{fontSize:10,marginTop:6,opacity:0.7,
              color:note.color==="default"?C.muted:"rgba(255,255,255,0.6)"}}>
              {done}/{checklist.length} done
            </div>
          )}
        </div>
      )}
      {/* Tags */}
      {(note.tags||[]).length>0&&(
        <div style={{display:"flex",gap:4,flexWrap:"wrap",marginTop:8}}>
          {note.tags.map(t=>(
            <span key={t} style={{fontSize:10,padding:"2px 7px",borderRadius:10,
              background:note.color==="default"?C.accentDim:"rgba(255,255,255,0.15)",
              color:note.color==="default"?C.accentText:"rgba(255,255,255,0.9)",
              cursor:"pointer"}}
              onClick={e=>{e.stopPropagation();onTagFilter(t);}}>
              #{t}
            </span>
          ))}
        </div>
      )}
      {/* Bottom actions — show on hover via opacity trick */}
      <div style={{display:"flex",gap:4,marginTop:10}}>
        <button onClick={e=>onArchive(note,e)}
          title="Archive"
          style={{background:"none",border:"none",cursor:"pointer",
            fontSize:13,opacity:0.4,padding:"2px 4px",
            color:note.color==="default"?C.muted:"#fff",lineHeight:1}}>
          📦
        </button>
        <button onClick={e=>onDelete(note,e)}
          title="Delete"
          style={{background:"none",border:"none",cursor:"pointer",
            fontSize:13,opacity:0.4,padding:"2px 4px",
            color:note.color==="default"?C.muted:"#fff",lineHeight:1}}>
          🗑
        </button>
        <span style={{fontSize:10,marginLeft:"auto",opacity:0.4,
          color:note.color==="default"?C.muted:"#fff",alignSelf:"center"}}>
          {note.updated_at?new Date(note.updated_at).toLocaleDateString():""}
        </span>
      </div>
    </div>
  );
}


function NoteEditor({editingNote,draftTitle,setDraftTitle,draftContent,setDraftContent,draftType,setDraftType,draftColor,setDraftColor,draftTags,setDraftTags,draftChecklist,setDraftChecklist,tagInput,setTagInput,showColorPicker,setShowColorPicker,saving,titleRef,onClose,onSave,addCheckItem,addTag,C}){
    const ns=getNoteStyle(draftColor,C);
  return(
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.6)",
      zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center",padding:16}}
      onClick={onClose}>
      <div onClick={e=>e.stopPropagation()}
        style={{width:"100%",maxWidth:560,...ns,borderRadius:16,
          boxShadow:"0 20px 60px rgba(0,0,0,0.5)",overflow:"hidden",
          maxHeight:"85vh",display:"flex",flexDirection:"column"}}>

        {/* Title */}
        <input ref={titleRef} value={draftTitle}
          onChange={e=>setDraftTitle(e.target.value)}
          placeholder="Title"
          style={{border:"none",outline:"none",padding:"16px 16px 0",
            fontSize:16,fontWeight:700,background:"transparent",
            color:draftColor==="default"?C.white||C.textHi:"#fff",
            fontFamily:"inherit",width:"100%",boxSizing:"border-box"}}/>

        {/* Content / Checklist */}
        <div style={{flex:1,overflowY:"auto",padding:"8px 16px"}}>
          {draftType==="text"&&(
            <textarea value={draftContent}
              onChange={e=>setDraftContent(e.target.value)}
              placeholder="Take a note..."
              rows={8}
              style={{border:"none",outline:"none",width:"100%",
                background:"transparent",resize:"vertical",
                fontSize:13,lineHeight:1.7,
                color:draftColor==="default"?C.text:"rgba(255,255,255,0.9)",
                fontFamily:"inherit",boxSizing:"border-box"}}/>
          )}
          {draftType==="checklist"&&(
            <div>
              {draftChecklist.map((item,idx)=>(
                <div key={idx} style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
                  <input type="checkbox" checked={item.checked}
                    onChange={()=>setDraftChecklist(p=>p.map((x,i)=>i===idx?{...x,checked:!x.checked}:x))}
                    style={{accentColor:draftColor==="default"?C.accent:"#fff",
                      width:15,height:15,flexShrink:0,cursor:"pointer"}}/>
                  <input value={item.text}
                    onChange={e=>setDraftChecklist(p=>p.map((x,i)=>i===idx?{...x,text:e.target.value}:x))}
                    placeholder="List item"
                    onKeyDown={e=>{
                      if(e.key==="Enter"){e.preventDefault();addCheckItem();}
                      if(e.key==="Backspace"&&!item.text&&draftChecklist.length>1){
                        e.preventDefault();
                        setDraftChecklist(p=>p.filter((_,i)=>i!==idx));
                      }
                    }}
                    style={{flex:1,border:"none",outline:"none",background:"transparent",
                      fontSize:13,fontFamily:"inherit",
                      textDecoration:item.checked?"line-through":"none",
                      opacity:item.checked?0.5:1,
                      color:draftColor==="default"?C.text:"rgba(255,255,255,0.9)"}}/>
                  <button onClick={()=>setDraftChecklist(p=>p.filter((_,i)=>i!==idx))}
                    style={{background:"none",border:"none",cursor:"pointer",
                      color:draftColor==="default"?C.muted:"rgba(255,255,255,0.5)",
                      fontSize:16,lineHeight:1,padding:"0 4px"}}>×</button>
                </div>
              ))}
              <button onClick={addCheckItem}
                style={{background:"none",border:"none",cursor:"pointer",
                  fontSize:12,color:draftColor==="default"?C.muted:"rgba(255,255,255,0.6)",
                  padding:"4px 0",fontFamily:"inherit",display:"flex",alignItems:"center",gap:8}}>
                + Add item
              </button>
            </div>
          )}
        </div>

        {/* Tags */}
        {draftTags.length>0&&(
          <div style={{display:"flex",gap:4,flexWrap:"wrap",padding:"0 16px 8px"}}>
            {draftTags.map(t=>(
              <span key={t} style={{fontSize:11,padding:"2px 8px",borderRadius:10,
                background:draftColor==="default"?C.accentDim:"rgba(255,255,255,0.15)",
                color:draftColor==="default"?C.accentText:"#fff",
                display:"flex",alignItems:"center",gap:4}}>
                #{t}
                <button onClick={()=>setDraftTags(p=>p.filter(x=>x!==t))}
                  style={{background:"none",border:"none",cursor:"pointer",padding:0,
                    color:"inherit",fontSize:14,lineHeight:1}}>×</button>
              </span>
            ))}
          </div>
        )}

        {/* Bottom toolbar */}
        <div style={{display:"flex",alignItems:"center",gap:8,padding:"8px 12px",
          borderTop:`1px solid rgba(255,255,255,0.1)`,flexWrap:"wrap"}}>

          {/* Type toggle */}
          <div style={{display:"flex",borderRadius:6,overflow:"hidden",border:`1px solid rgba(255,255,255,0.15)`}}>
            {[["text","📝"],["checklist","☑️"]].map(([t,icon])=>(
              <button key={t} onClick={()=>setDraftType(t)}
                style={{background:draftType===t?"rgba(255,255,255,0.2)":"transparent",
                  border:"none",cursor:"pointer",padding:"4px 12px",
                  fontSize:12,color:draftType===t?"#fff":"rgba(255,255,255,0.6)",
                  fontFamily:"inherit"}}>
                {icon} {t.charAt(0).toUpperCase()+t.slice(1)}
              </button>
            ))}
          </div>

          {/* Color picker */}
          <div style={{position:"relative"}}>
            <button onClick={()=>setShowColorPicker(p=>!p)}
              title="Change color"
              style={{background:showColorPicker?"rgba(255,255,255,0.2)":"transparent",
                border:"1px solid rgba(255,255,255,0.2)",borderRadius:6,cursor:"pointer",
                padding:"4px 12px",fontSize:12,color:"rgba(255,255,255,0.7)",fontFamily:"inherit"}}>
              🎨 Color
            </button>
            {showColorPicker&&(
              <div style={{position:"absolute",bottom:"calc(100% + 6px)",left:0,
                background:C.surface,border:`1px solid ${C.border}`,borderRadius:10,
                padding:10,display:"flex",flexWrap:"wrap",gap:8,width:200,zIndex:10,
                boxShadow:"0 8px 24px rgba(0,0,0,0.4)"}}>
                {NOTE_COLORS.map(nc=>(
                  <button key={nc.id} title={nc.label}
                    onClick={()=>{setDraftColor(nc.id);setShowColorPicker(false);}}
                    style={{width:28,height:28,borderRadius:14,cursor:"pointer",
                      background:nc.bg||C.surfaceHi,
                      border:`2px solid ${draftColor===nc.id?"#fff":nc.border||C.border}`,
                      boxShadow:draftColor===nc.id?"0 0 0 2px rgba(255,255,255,0.5)":"none"}}/>
                ))}
              </div>
            )}
          </div>

          {/* Tag add */}
          <div style={{display:"flex",gap:4}}>
            <input value={tagInput} onChange={e=>setTagInput(e.target.value)}
              onKeyDown={e=>{if(e.key==="Enter"){e.preventDefault();addTag();}}}
              placeholder="#tag"
              style={{width:80,border:"1px solid rgba(255,255,255,0.2)",borderRadius:6,
                background:"rgba(255,255,255,0.08)",color:"rgba(255,255,255,0.8)",
                padding:"4px 8px",fontSize:11,outline:"none",fontFamily:"inherit"}}/>
            <button onClick={addTag}
              style={{background:"rgba(255,255,255,0.1)",border:"1px solid rgba(255,255,255,0.2)",
                borderRadius:6,cursor:"pointer",padding:"4px 8px",
                fontSize:11,color:"rgba(255,255,255,0.7)",fontFamily:"inherit"}}>Add</button>
          </div>

          <div style={{marginLeft:"auto",display:"flex",gap:8}}>
            <button onClick={onClose}
              style={{background:"transparent",border:"1px solid rgba(255,255,255,0.2)",
                borderRadius:6,cursor:"pointer",padding:"5px 14px",
                fontSize:12,color:"rgba(255,255,255,0.7)",fontFamily:"inherit"}}>
              Discard
            </button>
            <button onClick={onSave} disabled={saving}
              style={{background:"rgba(255,255,255,0.9)",border:"none",borderRadius:6,
                cursor:"pointer",padding:"5px 14px",fontSize:12,fontWeight:700,
                color:"#1e293b",fontFamily:"inherit"}}>
              {saving?"Saving...":"Save"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}


// ── ADMIN WORKSPACE ───────────────────────────────────────────────────────────
const NOTE_COLORS = [
  {id:"default", bg:"",       border:"",       label:"Default"},
  {id:"red",     bg:"#7f1d1d",border:"#991b1b", label:"Red"},
  {id:"orange",  bg:"#7c2d12",border:"#9a3412", label:"Orange"},
  {id:"yellow",  bg:"#713f12",border:"#854d0e", label:"Yellow"},
  {id:"green",   bg:"#14532d",border:"#166534", label:"Green"},
  {id:"teal",    bg:"#134e4a",border:"#0f766e", label:"Teal"},
  {id:"blue",    bg:"#1e3a5f",border:"#1d4ed8", label:"Blue"},
  {id:"purple",  bg:"#3b0764",border:"#7e22ce", label:"Purple"},
  {id:"pink",    bg:"#500724",border:"#be185d", label:"Pink"},
  {id:"gray",    bg:"#1f2937",border:"#374151", label:"Gray"},
];

function getNoteStyle(colorId, C) {
  const nc = NOTE_COLORS.find(c=>c.id===colorId);
  if (!nc || colorId==="default") return {background:C.surface, border:`1px solid ${C.border}`};
  return {background:nc.bg, border:`1px solid ${nc.border}`};
}

function WorkspacePage({token,C}){
  const [notes,setNotes]=useState([]);
  const [loading,setLoading]=useState(true);
  const [q,setQ]=useState("");
  const [tagFilter,setTagFilter]=useState("");
  const [showArchived,setShowArchived]=useState(false);
  const [editingNote,setEditingNote]=useState(null); // null | note object | "new"
  const [draftTitle,setDraftTitle]=useState("");
  const [draftContent,setDraftContent]=useState("");
  const [draftType,setDraftType]=useState("text");
  const [draftColor,setDraftColor]=useState("default");
  const [draftTags,setDraftTags]=useState([]);
  const [draftChecklist,setDraftChecklist]=useState([]);
  const [draftLinkedIocs,setDraftLinkedIocs]=useState([]);
  const [draftLinkedCves,setDraftLinkedCves]=useState([]);
  const [tagInput,setTagInput]=useState("");
  const [saving,setSaving]=useState(false);
  const [showColorPicker,setShowColorPicker]=useState(false);
  const titleRef=useRef(null);

  // All unique tags across notes for filter bar
  const allTags=[...new Set(notes.flatMap(n=>n.tags||[]))].sort();

  useEffect(()=>{loadNotes();},[q,tagFilter,showArchived]);// eslint-disable-line react-hooks/exhaustive-deps

  async function loadNotes(){
    setLoading(true);
    const params=new URLSearchParams({q,archived:showArchived,tag:tagFilter});
    const r=await api(`/workspace/notes?${params}`,{},token);
    if(r.ok) setNotes(await r.json());
    setLoading(false);
  }

  function openNew(){
    setDraftTitle(""); setDraftContent(""); setDraftType("text");
    setDraftColor("default"); setDraftTags([]); setDraftChecklist([]);
    setDraftLinkedIocs([]); setDraftLinkedCves([]);
    setTagInput(""); setShowColorPicker(false);
    setEditingNote("new");
    setTimeout(()=>titleRef.current?.focus(),50);
  }

  function openEdit(note){
    setDraftTitle(note.title||"");
    setDraftContent(note.content||"");
    setDraftType(note.note_type||"text");
    setDraftColor(note.color||"default");
    setDraftTags(note.tags||[]);
    setDraftChecklist((note.checklist||[]).map(i=>typeof i==="string"?{text:i,checked:false}:i));
    setDraftLinkedIocs(note.linked_iocs||[]);
    setDraftLinkedCves(note.linked_cves||[]);
    setTagInput(""); setShowColorPicker(false);
    setEditingNote(note);
  }

  function closeEdit(){ setEditingNote(null); }

  async function saveNote(){
    if(!draftTitle.trim()&&!draftContent.trim()&&draftChecklist.length===0){
      closeEdit(); return;
    }
    setSaving(true);
    const body={title:draftTitle, content:draftContent, note_type:draftType,
      color:draftColor, tags:draftTags, checklist:draftChecklist,
      pinned:editingNote==="new"?false:(editingNote?.pinned||false),
      archived:false, linked_iocs:draftLinkedIocs, linked_cves:draftLinkedCves};
    let r;
    if(editingNote==="new"){
      r=await api("/workspace/notes",{method:"POST",body:JSON.stringify(body)},token);
    } else {
      r=await api(`/workspace/notes/${editingNote.id}`,{method:"PATCH",body:JSON.stringify(body)},token);
    }
    if(r.ok){ closeEdit(); loadNotes(); }
    setSaving(false);
  }

  async function togglePin(note,e){
    e.stopPropagation();
    const body={...note, pinned:!note.pinned,
      tags:note.tags||[], checklist:note.checklist||[],
      linked_iocs:note.linked_iocs||[], linked_cves:note.linked_cves||[]};
    const r=await api(`/workspace/notes/${note.id}`,{method:"PATCH",body:JSON.stringify(body)},token);
    if(r.ok) loadNotes();
  }

  async function archiveNote(note,e){
    e.stopPropagation();
    const body={...note, archived:true,
      tags:note.tags||[], checklist:note.checklist||[],
      linked_iocs:note.linked_iocs||[], linked_cves:note.linked_cves||[]};
    const r=await api(`/workspace/notes/${note.id}`,{method:"PATCH",body:JSON.stringify(body)},token);
    if(r.ok) loadNotes();
  }

  async function deleteNote(note,e){
    e.stopPropagation();
    if(!window.confirm("Delete this note permanently?")) return;
    const r=await api(`/workspace/notes/${note.id}`,{method:"DELETE"},token);
    if(r.ok) loadNotes();
  }

  async function toggleCheckItem(note,idx){
    const cl=(note.checklist||[]).map((item,i)=>
      i===idx?{...item,checked:!item.checked}:item);
    const body={...note,checklist:cl,
      tags:note.tags||[],linked_iocs:note.linked_iocs||[],linked_cves:note.linked_cves||[]};
    const r=await api(`/workspace/notes/${note.id}`,{method:"PATCH",body:JSON.stringify(body)},token);
    if(r.ok) loadNotes();
  }

  function addTag(){
    const t=tagInput.trim().toLowerCase().replace(/\s+/g,"-");
    if(t&&!draftTags.includes(t)){setDraftTags(p=>[...p,t]);}
    setTagInput("");
  }

  function addCheckItem(){
    setDraftChecklist(p=>[...p,{text:"",checked:false}]);
  }

  const pinned=notes.filter(n=>n.pinned);
  const unpinned=notes.filter(n=>!n.pinned);


  // Edit / Create modal

  return(
    <div style={{maxWidth:1000}}>
      {/* Header */}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20,flexWrap:"wrap",gap:12}}>
        <div style={{fontSize:18,fontWeight:700,color:C.white||C.textHi}}>
          Workspace
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center",flex:1,maxWidth:400}}>
          <div style={{flex:1,position:"relative"}}>
            <input value={q} onChange={e=>setQ(e.target.value)}
              placeholder="Search notes..."
              style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                color:C.inputText,padding:"8px 12px 8px 32px",borderRadius:8,
                fontSize:13,outline:"none",fontFamily:"inherit",boxSizing:"border-box"}}/>
            <span style={{position:"absolute",left:10,top:"50%",transform:"translateY(-50%)",
              color:C.muted,fontSize:14}}>🔍</span>
          </div>
          <button onClick={openNew}
            style={{padding:"8px 18px",borderRadius:8,cursor:"pointer",fontFamily:"inherit",
              fontSize:13,fontWeight:700,background:C.accent,border:"none",color:"#fff",
              flexShrink:0}}>
            + New Note
          </button>
        </div>
      </div>

      {/* Tag filter bar */}
      {allTags.length>0&&(
        <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:16}}>
          <button onClick={()=>setTagFilter("")}
            style={{fontSize:11,padding:"4px 12px",borderRadius:10,cursor:"pointer",
              border:`1px solid ${!tagFilter?C.accent:C.border}`,
              background:!tagFilter?C.accentDim:"transparent",
              color:!tagFilter?C.accentText:C.muted,fontFamily:"inherit"}}>
            All
          </button>
          {allTags.map(t=>(
            <button key={t} onClick={()=>setTagFilter(t===tagFilter?"":t)}
              style={{fontSize:11,padding:"4px 12px",borderRadius:10,cursor:"pointer",
                border:`1px solid ${tagFilter===t?C.accent:C.border}`,
                background:tagFilter===t?C.accentDim:"transparent",
                color:tagFilter===t?C.accentText:C.muted,fontFamily:"inherit"}}>
              #{t}
            </button>
          ))}
          <button onClick={()=>setShowArchived(p=>!p)}
            style={{fontSize:11,padding:"4px 12px",borderRadius:10,cursor:"pointer",
              border:`1px solid ${showArchived?C.amber:C.border}`,
              background:showArchived?C.amber+"15":"transparent",
              color:showArchived?C.amber:C.muted,fontFamily:"inherit",marginLeft:"auto"}}>
            {showArchived?"Hide archived":"Show archived"}
          </button>
        </div>
      )}

      {loading&&<div style={{textAlign:"center",padding:48,color:C.muted}}>Loading workspace...</div>}

      {!loading&&notes.length===0&&(
        <div style={{textAlign:"center",padding:64,color:C.muted}}>
          <div style={{fontSize:40,marginBottom:12}}>📝</div>
          <div style={{fontSize:14,fontWeight:600,color:C.white||C.textHi,marginBottom:8}}>
            {q||tagFilter?"No notes match your search":"Your workspace is empty"}
          </div>
          <div style={{fontSize:12,marginBottom:20}}>
            Notes, checklists, threat intel context — keep everything in one place.
          </div>
          {!q&&!tagFilter&&(
            <button onClick={openNew}
              style={{padding:"8px 20px",borderRadius:8,cursor:"pointer",fontFamily:"inherit",
                fontSize:13,fontWeight:700,background:C.accent,border:"none",color:"#fff"}}>
              Create your first note
            </button>
          )}
        </div>
      )}

      {/* Pinned section */}
      {pinned.length>0&&(
        <div style={{marginBottom:20}}>
          <div style={{fontSize:10,fontWeight:700,color:C.muted,textTransform:"uppercase",
            letterSpacing:"0.08em",marginBottom:10}}>📌 Pinned</div>
          <div style={{columns:"2 300px",columnGap:12}}>
            {pinned.map(n=><NoteCard key={n.id} note={n} onEdit={openEdit} onTogglePin={togglePin} onArchive={archiveNote} onDelete={deleteNote} onToggleCheck={toggleCheckItem} onTagFilter={setTagFilter} C={C}/>)}
          </div>
        </div>
      )}

      {/* Other notes */}
      {unpinned.length>0&&(
        <div>
          {pinned.length>0&&<div style={{fontSize:10,fontWeight:700,color:C.muted,
            textTransform:"uppercase",letterSpacing:"0.08em",marginBottom:10}}>Other</div>}
          <div style={{columns:"2 300px",columnGap:12}}>
            {unpinned.map(n=><NoteCard key={n.id} note={n} onEdit={openEdit} onTogglePin={togglePin} onArchive={archiveNote} onDelete={deleteNote} onToggleCheck={toggleCheckItem} onTagFilter={setTagFilter} C={C}/>)}
          </div>
        </div>
      )}

      {editingNote&&<NoteEditor
        editingNote={editingNote}
        draftTitle={draftTitle} setDraftTitle={setDraftTitle}
        draftContent={draftContent} setDraftContent={setDraftContent}
        draftType={draftType} setDraftType={setDraftType}
        draftColor={draftColor} setDraftColor={setDraftColor}
        draftTags={draftTags} setDraftTags={setDraftTags}
        draftChecklist={draftChecklist} setDraftChecklist={setDraftChecklist}
        tagInput={tagInput} setTagInput={setTagInput}
        showColorPicker={showColorPicker} setShowColorPicker={setShowColorPicker}
        saving={saving} titleRef={titleRef}
        onClose={closeEdit} onSave={saveNote}
        addCheckItem={addCheckItem} addTag={addTag}
        C={C}
      />}
    </div>
  );
}



function AdvisoryBuilder({token,C}){
  const [iocPool,setIocPool]=useState([]);
  const [poolLoading,setPoolLoading]=useState(true);
  const [familyFilter,setFamilyFilter]=useState("fintech");
  const [typeFilter,setTypeFilter]=useState("");
  const [selectedIocIds,setSelectedIocIds]=useState(new Set());
  const [suggestedCves,setSuggestedCves]=useState([]);
  const [cveLoading,setCveLoading]=useState(true);
  const [cveSearch,setCveSearch]=useState("");
  const [cveSearching,setCveSearching]=useState(false);
  const [selectedCves,setSelectedCves]=useState([]);
  const [clientName,setClientName]=useState("");
  const [analystName,setAnalystName]=useState("");
  const [sector,setSector]=useState("Financial Services / Fintech");
  const [tlp,setTlp]=useState("AMBER");
  const [customNote,setCustomNote]=useState("");
  const [generating,setGenerating]=useState(false);
  const [result,setResult]=useState(null);
  const [err,setErr]=useState("");

  const MAX_IOCS=5; const MAX_CVES=2;

  // Unique malware families in pool for filter dropdown
  const families=[...new Set(iocPool.map(i=>i.family).filter(Boolean))].sort();

  useEffect(()=>{
    loadPool(familyFilter);
    // Load suggested CVEs from CISA KEV + EPSS on mount
    setCveLoading(true);
    api("/advisory/suggested-cves?limit=15&days=45",{},token)
      .then(r=>r.ok?r.json():[])
      .then(d=>{setSuggestedCves(d);setCveLoading(false);})
      .catch(()=>setCveLoading(false));
  },[]);// eslint-disable-line react-hooks/exhaustive-deps

  const [rescanning,setRescanning]=useState({});   // ioc id -> true while in flight
  const [rescanned,setRescanned]=useState({});     // ioc id -> {confidence, verdict, at}

  // Re-runs live enrichment (VirusTotal / AbuseIPDB / URLhaus) against the
  // indicator so you can confirm it is still considered malicious before it
  // goes out to a client, rather than trusting a score captured days ago.
  async function rescan(ioc,e){
    if(e) e.stopPropagation();
    setRescanning(r=>({...r,[ioc.id]:true}));
    try{
      const r=await api(`/iocs/${ioc.id}/re-enrich`,{method:"POST"},token);
      if(r.ok){
        const d=await r.json();
        const conf=typeof d.confidence==="number"?d.confidence:ioc.confidence;
        setRescanned(m=>({...m,[ioc.id]:{confidence:conf,at:Date.now(),
          verdict:conf>=70?"malicious":conf>=40?"suspicious":"clean"}}));
        setIocPool(pool=>pool.map(x=>x.id===ioc.id?{...x,confidence:conf}:x));
      }else{
        setRescanned(m=>({...m,[ioc.id]:{error:`Re-scan failed (${r.status})`,at:Date.now()}}));
      }
    }catch(err){
      setRescanned(m=>({...m,[ioc.id]:{error:String(err.message||err),at:Date.now()}}));
    }
    setRescanning(r=>{const n={...r};delete n[ioc.id];return n;});
  }

  // Sequential on purpose: these calls each hit third-party APIs with their own
  // rate limits, and a burst of parallel re-scans burns quota for no gain.
  async function rescanSelected(){
    const targets=iocPool.filter(i=>selectedIocIds.has(i.id));
    for(const t of targets){ await rescan(t); }
  }

  async function loadPool(fam){
    setPoolLoading(true);
    const params=new URLSearchParams({sector:fam==="fintech"?"fintech":"",family:fam==="fintech"?"":fam,limit:80});
    if(typeFilter) params.set("ioc_type",typeFilter);
    const r=await api(`/advisory/iocs?${params}`,{},token);
    if(r.ok) setIocPool(await r.json());
    setPoolLoading(false);
  }

  function toggleIoc(id){
    setSelectedIocIds(prev=>{
      const n=new Set(prev);
      if(n.has(id)) n.delete(id);
      else if(n.size<MAX_IOCS) n.add(id);
      return n;
    });
  }

  async function searchCve(){
    const q=cveSearch.trim().toUpperCase();
    if(!q.startsWith("CVE-")||selectedCves.some(c=>c.id===q)) return;
    if(selectedCves.length>=MAX_CVES){setErr(`Max ${MAX_CVES} CVEs`);return;}
    setCveSearching(true);setErr("");
    const r=await api(`/cve/lookup?id=${q}`,{},token);
    if(r.ok){
      const d=await r.json();
      const nvd=d.sources?.find(s=>s.source==="NVD")||d.sources?.[0]||{};
      setSelectedCves(p=>[...p,{
        id:q,
        description:(nvd.description||"No description available.").slice(0,400),
        cvss_score: nvd.cvss_score||"N/A",
        severity:   nvd.severity||"UNKNOWN",
      }]);
      setCveSearch("");
    } else setErr("CVE not found");
    setCveSearching(false);
  }

  async function generate(){
    if(!clientName.trim()){setErr("Client name is required.");return;}
    if(selectedIocIds.size===0&&selectedCves.length===0){setErr("Select at least one IOC or CVE.");return;}
    setGenerating(true);setErr("");setResult(null);
    const r=await api("/advisory/generate",{method:"POST",body:JSON.stringify({
      ioc_ids:[...selectedIocIds], cve_ids:selectedCves.map(c=>c.id),
      client_name:clientName, analyst_name:analystName||"TFII Analyst",
      sector, tlp, custom_note:customNote,
    })},token);
    if(r.ok) setResult(await r.json());
    else{const e=await r.json();setErr(e.detail||"Generation failed.");}
    setGenerating(false);
  }

  function downloadEml(){
    if(!result) return;
    const boundary="----=_Part_TFII_"+Date.now();
    const eml=[
      `MIME-Version: 1.0`,
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
      `Subject: ${result.subject}`,
      `From: TFII Advisory <noreply@tfii.dev>`,
      ``,
      `--${boundary}`,
      `Content-Type: text/plain; charset=UTF-8`,
      `Content-Transfer-Encoding: 7bit`,
      ``,
      result.plain_text||"",
      ``,
      `--${boundary}`,
      `Content-Type: text/html; charset=UTF-8`,
      `Content-Transfer-Encoding: 7bit`,
      ``,
      result.html||"",
      ``,
      `--${boundary}--`,
    ].join("\r\n");
    const blob=new Blob([eml],{type:"message/rfc822"});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url; a.download=`TFII-Advisory-${clientName.replace(/\s+/g,"-")}.eml`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  const TLP_COLORS={RED:"#dc2626",AMBER:"#d97706",GREEN:"#16a34a",WHITE:"#6b7280"};

  if(result){
    return(
      <div style={{maxWidth:900}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16,flexWrap:"wrap",gap:12}}>
          <div>
            <div style={{fontSize:16,fontWeight:700,color:C.white||C.textHi}}>Advisory Preview</div>
            <div style={{fontSize:11,color:C.muted}}>{result.subject}</div>
          </div>
          <div style={{display:"flex",gap:8}}>
            <Btn onClick={downloadEml} C={C}>📧 Download .eml (Open in Mail)</Btn>
            <Btn onClick={()=>setResult(null)} variant="ghost" C={C}>← Edit</Btn>
          </div>
        </div>
        <div style={{background:"#fff",borderRadius:12,overflow:"hidden",boxShadow:"0 4px 24px rgba(0,0,0,0.15)"}}>
          <iframe
            srcDoc={result.html}
            title="Advisory Preview"
            style={{width:"100%",minHeight:700,border:"none",display:"block"}}
            sandbox="allow-same-origin"
          />
        </div>
        <div style={{marginTop:12,fontSize:11,color:C.muted,textAlign:"center"}}>
          Download the .eml file and open it in Outlook, Apple Mail, or Thunderbird to send directly to your client.
        </div>
      </div>
    );
  }

  return(
    <div style={{maxWidth:1000}}>
      <div style={{marginBottom:20}}>
        <div style={{fontSize:16,fontWeight:700,color:C.white||C.textHi,marginBottom:4}}>Client Advisory Builder</div>
        <div style={{fontSize:12,color:C.muted}}>Select IOCs from connector feeds + CVEs → generate a professional HTML advisory email.</div>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:16}}>
        {/* ── IOC Picker ── */}
        <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:"16px",boxShadow:C.shadow}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12,flexWrap:"wrap",gap:8}}>
            <div>
              <div style={{fontSize:13,fontWeight:700,color:C.white||C.textHi}}>Threat Indicators</div>
              <div style={{fontSize:10,color:C.muted}}>Select up to {MAX_IOCS} — {selectedIocIds.size} selected</div>
            </div>
            <div style={{display:"flex",gap:8}}>
              <select value={familyFilter} onChange={e=>setFamilyFilter(e.target.value)}
                style={{fontSize:11,background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"4px 8px",borderRadius:6,fontFamily:"inherit"}}>
                <option value="fintech">🏦 Fintech / GCC</option>
                {families.map(f=><option key={f} value={f}>{f}</option>)}
                <option value="">All families</option>
              </select>
              <select value={typeFilter} onChange={e=>setTypeFilter(e.target.value)}
                style={{fontSize:11,background:C.inputBg,border:`1px solid ${C.inputBorder}`,color:C.inputText,padding:"4px 8px",borderRadius:6,fontFamily:"inherit"}}>
                <option value="">All types</option>
                {["IPv4","Domain","URL","MD5","SHA256"].map(t=><option key={t} value={t}>{t}</option>)}
              </select>
              <button onClick={rescanSelected}
                disabled={selectedIocIds.size===0||Object.keys(rescanning).length>0}
                title="Re-check every selected indicator against live sources before it goes to a client"
                style={{fontSize:11,padding:"4px 12px",borderRadius:6,fontFamily:"inherit",fontWeight:600,
                  cursor:selectedIocIds.size===0?"not-allowed":"pointer",
                  background:selectedIocIds.size?C.accentDim:"transparent",
                  border:`1px solid ${selectedIocIds.size?C.accent+"55":C.border}`,
                  color:selectedIocIds.size?C.accentText:C.muted,
                  opacity:Object.keys(rescanning).length?0.6:1}}>
                {Object.keys(rescanning).length?"Re-scanning…":`Re-scan selected (${selectedIocIds.size})`}
              </button>
            </div>
          </div>
          <div style={{maxHeight:340,overflowY:"auto",display:"flex",flexDirection:"column",gap:4}}>
            {poolLoading&&<div style={{textAlign:"center",padding:24,color:C.muted,fontSize:12}}>Loading...</div>}
            {!poolLoading&&iocPool.length===0&&(
              <div style={{textAlign:"center",padding:24,color:C.muted,fontSize:12}}>
                No connector IOCs found for this filter.<br/>
                Go to Admin → Connectors and run a sync first.
              </div>
            )}
            {iocPool.map(ioc=>{
              const sel=selectedIocIds.has(ioc.id);
              const disabled=!sel&&selectedIocIds.size>=MAX_IOCS;
              return(
                <div key={ioc.id} onClick={()=>!disabled&&toggleIoc(ioc.id)}
                  style={{display:"flex",alignItems:"center",gap:8,padding:"8px 12px",
                    borderRadius:8,cursor:disabled?"not-allowed":"pointer",
                    background:sel?C.accentDim:C.surfaceHi,
                    border:`1px solid ${sel?C.accent:C.border}`,
                    opacity:disabled?0.4:1}}>
                  <input type="checkbox" checked={sel} readOnly
                    style={{accentColor:C.accent,flexShrink:0,cursor:"pointer"}}/>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
                      <span style={{fontSize:10,padding:"1px 6px",borderRadius:3,fontWeight:700,
                        background:C.accentDim,color:C.accentText}}>{ioc.type}</span>
                      {ioc.family&&<span style={{fontSize:10,padding:"1px 6px",borderRadius:3,
                        background:C.red+"15",color:C.red,fontWeight:600}}>{ioc.family}</span>}
                      <span style={{fontSize:9,color:C.muted}}>{ioc.source}</span>
                    </div>
                    <div style={{fontSize:11,fontFamily:"monospace",color:C.text,marginTop:3,
                      wordBreak:"break-all",lineHeight:1.3}}>{ioc.value}</div>
                  </div>
                  <div style={{display:"flex",alignItems:"center",gap:8,flexShrink:0}}>
                    {(()=>{ const r=rescanned[ioc.id];
                      if(!r) return <span style={{fontSize:10,color:C.muted}}>{ioc.confidence}%</span>;
                      if(r.error) return <span style={{fontSize:9.5,color:C.red}} title={r.error}>re-scan failed</span>;
                      const col=r.verdict==="malicious"?C.red:r.verdict==="suspicious"?C.amber:C.green;
                      return(
                        <span style={{display:"inline-flex",alignItems:"center",gap:5}}>
                          <span style={{fontSize:9,padding:"1px 6px",borderRadius:3,fontWeight:700,
                            background:col+"1e",color:col}}>{r.verdict}</span>
                          <span style={{fontSize:10,color:col,fontWeight:600}}>{r.confidence}%</span>
                        </span>
                      );
                    })()}
                    <button onClick={e=>rescan(ioc,e)} disabled={!!rescanning[ioc.id]}
                      title="Re-check this indicator against VirusTotal / AbuseIPDB / URLhaus"
                      style={{fontSize:9.5,padding:"2px 7px",borderRadius:5,fontFamily:"inherit",
                        fontWeight:600,cursor:rescanning[ioc.id]?"wait":"pointer",
                        background:"transparent",border:`1px solid ${C.border}`,
                        color:rescanning[ioc.id]?C.muted:C.accentText}}>
                      {rescanning[ioc.id]?"…":"Re-scan"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* ── CVE Picker ── */}
        <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,padding:"16px",boxShadow:C.shadow,display:"flex",flexDirection:"column"}}>
          <div style={{fontSize:13,fontWeight:700,color:C.white||C.textHi,marginBottom:2}}>CVE Advisories</div>
          <div style={{fontSize:10,color:C.muted,marginBottom:10}}>Surfaced from CISA KEV + EPSS · Actively exploited · Widely-used tech only</div>
          <div style={{display:"flex",gap:8,marginBottom:10}}>
            <input value={cveSearch} onChange={e=>setCveSearch(e.target.value)}
              onKeyDown={e=>e.key==="Enter"&&searchCve()}
              placeholder="Or add specific CVE-XXXX-XXXXX"
              style={{flex:1,background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                color:C.inputText,padding:"8px 12px",borderRadius:6,fontSize:12,
                outline:"none",fontFamily:"monospace"}}/>
            <Btn onClick={searchCve} disabled={cveSearching||selectedCves.length>=MAX_CVES} C={C}>{cveSearching?"...":"Add"}</Btn>
          </div>
          {selectedCves.length>0&&(
            <div style={{marginBottom:10}}>
              {selectedCves.map(cve=>{
                const sc=cve.severity==="CRITICAL"?C.red:cve.severity==="HIGH"?C.amber:C.muted;
                return(
                  <div key={cve.id} style={{padding:"8px 12px",marginBottom:6,background:C.accentDim,
                    border:`1px solid ${C.accent}40`,borderRadius:7,
                    display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
                    <div style={{flex:1}}>
                      <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap",marginBottom:3}}>
                        <span style={{fontSize:11,fontWeight:700,color:C.accentText}}>{cve.id}</span>
                        {cve.severity&&<span style={{fontSize:10,padding:"1px 5px",borderRadius:3,
                          fontWeight:700,background:sc+"15",color:sc}}>{cve.severity} {cve.cvss_score||""}</span>}
                        {cve.kev_date&&<span style={{fontSize:9,color:C.muted}}>KEV {cve.kev_date}</span>}
                        {cve.ransomware&&<span style={{fontSize:9,padding:"1px 5px",borderRadius:3,
                          background:C.red+"15",color:C.red,fontWeight:700}}>🔒 Ransomware</span>}
                      </div>
                      <div style={{fontSize:10,color:C.muted,lineHeight:1.4}}>
                        <strong style={{color:C.text}}>{cve.vendor} {cve.product}</strong>
                        {" — "}{(cve.name||cve.description||"").slice(0,100)}
                      </div>
                    </div>
                    <button onClick={()=>setSelectedCves(p=>p.filter(c=>c.id!==cve.id))}
                      style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:16,lineHeight:1,marginLeft:8,flexShrink:0}}>×</button>
                  </div>
                );
              })}
            </div>
          )}
          <div style={{flex:1,overflowY:"auto",maxHeight:300}}>
            {cveLoading&&<SlowLoader C={C} pad={16}
              message="Cross-referencing CISA KEV and EPSS"
              hint="This checks every recent KEV entry against exploit-probability scores — it usually takes 10-20 seconds."/>}
            {!cveLoading&&suggestedCves.length===0&&<div style={{textAlign:"center",padding:16,color:C.muted,fontSize:12}}>No recent KEV matches. Use the search box above.</div>}
            {!cveLoading&&suggestedCves.map(cve=>{
              const already=selectedCves.some(s=>s.id===cve.id);
              const disabled=!already&&selectedCves.length>=MAX_CVES;
              const sc=cve.severity==="CRITICAL"?C.red:cve.severity==="HIGH"?C.amber:C.muted;
              return(
                <div key={cve.id} onClick={()=>{
                    if(disabled||already)return;
                    setSelectedCves(p=>[...p,{id:cve.id,description:cve.description,name:cve.name,
                      cvss_score:cve.cvss_score,severity:cve.severity,vendor:cve.vendor,
                      product:cve.product,kev_date:cve.kev_date,ransomware:cve.ransomware,epss_pct:cve.epss_pct}]);
                  }}
                  style={{padding:"8px 12px",marginBottom:5,borderRadius:7,cursor:disabled?"not-allowed":"pointer",
                    background:already?C.accentDim:C.surfaceHi,border:`1px solid ${already?C.accent:C.border}`,opacity:disabled?0.4:1}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{display:"flex",gap:4,alignItems:"center",flexWrap:"wrap",marginBottom:3}}>
                        <span style={{fontSize:11,fontWeight:700,color:already?C.accentText:C.text,fontFamily:"monospace"}}>{cve.id}</span>
                        {cve.severity&&<span style={{fontSize:9,padding:"1px 5px",borderRadius:3,fontWeight:700,background:sc+"20",color:sc}}>{cve.severity}{cve.cvss_score?` ${cve.cvss_score}`:""}</span>}
                        {cve.ransomware&&<span style={{fontSize:9,padding:"1px 5px",borderRadius:3,background:C.red+"15",color:C.red,fontWeight:700}}>🔒 Ransomware</span>}
                        {cve.epss_pct!=null&&<span style={{fontSize:9,color:C.muted}}>EPSS {cve.epss_pct}%ile</span>}
                      </div>
                      <div style={{fontSize:10,color:C.muted,lineHeight:1.4}}>
                        <span style={{fontWeight:600,color:C.text}}>{cve.vendor}</span>{" "}{cve.product}{" — "}{(cve.name||"").slice(0,80)}
                      </div>
                    </div>
                    <div style={{flexShrink:0,marginLeft:8,textAlign:"right"}}>
                      {cve.kev_date&&<div style={{fontSize:9,color:C.muted}}>KEV {cve.kev_date}</div>}
                      {already&&<div style={{fontSize:10,color:C.accentText,fontWeight:600}}>✓</div>}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          {selectedCves.length>=MAX_CVES&&<div style={{fontSize:10,color:C.amber,marginTop:6,textAlign:"center"}}>Max {MAX_CVES} CVEs selected</div>}
        </div>
      </div>

      {/* ── Advisory Config ── */}
      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
        padding:"16px 20px",marginBottom:16,boxShadow:C.shadow}}>
        <div style={{fontSize:13,fontWeight:700,color:C.white||C.textHi,marginBottom:14}}>Advisory Details</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
          {[["Client / Organisation *",clientName,setClientName,"ACME Fintech Ltd"],
            ["Analyst Name",analystName,setAnalystName,"Your name"]].map(([label,val,set,ph])=>(
            <div key={label}>
              <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4}}>{label}</div>
              <input value={val} onChange={e=>set(e.target.value)} placeholder={ph}
                style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                  color:C.inputText,padding:"8px 12px",borderRadius:7,fontSize:13,
                  outline:"none",fontFamily:"inherit",boxSizing:"border-box"}}/>
            </div>
          ))}
          <div>
            <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4}}>Sector</div>
            <input value={sector} onChange={e=>setSector(e.target.value)}
              style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                color:C.inputText,padding:"8px 12px",borderRadius:7,fontSize:13,
                outline:"none",fontFamily:"inherit",boxSizing:"border-box"}}/>
          </div>
          <div>
            <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4}}>TLP Classification</div>
            <div style={{display:"flex",gap:8}}>
              {["WHITE","GREEN","AMBER","RED"].map(t=>(
                <button key={t} onClick={()=>setTlp(t)}
                  style={{flex:1,padding:"7px 4px",borderRadius:6,cursor:"pointer",fontFamily:"inherit",
                    fontSize:11,fontWeight:700,border:`2px solid ${tlp===t?TLP_COLORS[t]:C.border}`,
                    background:tlp===t?TLP_COLORS[t]+"20":"transparent",
                    color:tlp===t?TLP_COLORS[t]:C.muted}}>
                  {t}
                </button>
              ))}
            </div>
          </div>
        </div>
        <div>
          <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4}}>Additional Context (optional)</div>
          <textarea value={customNote} onChange={e=>setCustomNote(e.target.value)}
            placeholder="e.g. Client is expanding into Pakistan market. Focus on mobile banking threats."
            rows={2}
            style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
              color:C.inputText,padding:"8px 12px",borderRadius:7,fontSize:12,
              outline:"none",fontFamily:"inherit",resize:"vertical",boxSizing:"border-box"}}/>
        </div>
      </div>

      {/* ── Summary + Generate ── */}
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:12}}>
        <div style={{fontSize:12,color:C.muted}}>
          <span style={{color:selectedIocIds.size>0?C.accentText:C.muted,fontWeight:600}}>
            {selectedIocIds.size} IOC{selectedIocIds.size!==1?"s":""}
          </span>
          <span style={{margin:"0 8px",color:C.border}}>·</span>
          <span style={{color:selectedCves.length>0?C.accentText:C.muted,fontWeight:600}}>
            {selectedCves.length} CVE{selectedCves.length!==1?"s":""}
          </span>
          <span style={{margin:"0 8px",color:C.border}}>·</span>
          <span style={{padding:"2px 8px",borderRadius:4,fontWeight:700,fontSize:11,
            background:(TLP_COLORS[tlp]||C.muted)+"20",color:TLP_COLORS[tlp]||C.muted}}>
            TLP:{tlp}
          </span>
          {clientName&&<span style={{marginLeft:8}}>for <strong style={{color:C.text}}>{clientName}</strong></span>}
        </div>
        <Btn onClick={generate} disabled={generating||(!selectedIocIds.size&&!selectedCves.length)||!clientName} C={C}>
          {generating?"Generating Advisory...":"✉ Generate Advisory"}
        </Btn>
      </div>
      {err&&<div style={{marginTop:10,fontSize:12,color:C.red,fontWeight:600}}>{err}</div>}
    </div>
  );
}

// ── THREAT FEED CONNECTORS PAGE ───────────────────────────────────────────────
function HealthPage({token,C}){
  const [data,setData]=useState(null);
  const [loading,setLoading]=useState(false);
  const [lastRun,setLastRun]=useState(null);

  async function runCheck(){
    setLoading(true);
    const r=await api("/admin/health",{},token);
    if(r.ok){setData(await r.json());setLastRun(new Date());}
    setLoading(false);
  }

  useEffect(()=>{runCheck();},[]);// eslint-disable-line react-hooks/exhaustive-deps

  function StatusDot({ok}){
    return <span style={{display:"inline-block",width:10,height:10,borderRadius:"50%",
      background:ok?C.green:C.red,flexShrink:0,marginTop:2}}/>;
  }

  function CheckCard({title,check}){
    if(!check) return null;
    const ok=check.ok!==false;
    return(
      <div style={{background:C.surfaceHi,border:`1px solid ${ok?C.border:C.red+"40"}`,
        borderRadius:10,padding:"12px 16px"}}>
        <div style={{display:"flex",alignItems:"flex-start",gap:12,marginBottom:ok?0:8}}>
          <StatusDot ok={ok}/>
          <div style={{flex:1}}>
            <div style={{fontSize:12,fontWeight:700,color:C.white||C.textHi}}>{title}</div>
            <div style={{fontSize:11,color:ok?C.muted:C.red,marginTop:2}}>{check.status||""}</div>
          </div>
        </div>
        {/* Extra detail rows */}
        {check.iocs!==undefined&&(
          <div style={{display:"flex",gap:16,marginTop:8,flexWrap:"wrap"}}>
            {[["IOCs",check.iocs],["CVE Findings",check.cve_findings],["Assets",check.assets],["Users",check.active_users]].map(([l,v])=>v!==undefined&&(
              <div key={l} style={{fontSize:11,color:C.muted}}>
                <span style={{fontWeight:600,color:C.text}}>{v}</span> {l}
              </div>
            ))}
          </div>
        )}
        {check.used_pct!==undefined&&(
          <div style={{marginTop:8}}>
            <div style={{height:4,background:C.border,borderRadius:2,overflow:"hidden"}}>
              <div style={{width:`${Math.min(check.used_pct,100)}%`,height:"100%",borderRadius:2,
                background:check.used_pct>90?C.red:check.used_pct>75?C.amber:C.green}}/>
            </div>
          </div>
        )}
        {check.age_hours!==undefined&&(
          <div style={{marginTop:8,fontSize:11,color:C.muted}}>
            Polled {check.assets_polled} assets · {check.new_cves} new CVEs · {check.patches_detected} patches
          </div>
        )}
      </div>
    );
  }

  function ApiKeyRow({svc,info}){
    const labels={virustotal:"VirusTotal",abuseipdb:"AbuseIPDB",urlhaus:"URLhaus",
      shodan:"Shodan",groq:"Groq",nvd:"NVD"};
    return(
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",
        padding:"6px 0",borderBottom:`1px solid ${C.border}20`}}>
        <span style={{fontSize:12,color:C.text}}>{labels[svc]||svc}</span>
        <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:600,
          background:info.configured?C.green+"15":C.surfaceHi,
          color:info.configured?C.green:C.muted}}>
          {info.configured ? info.source : "not configured"}
        </span>
      </div>
    );
  }

  function ConnRow({name,check}){
    return(
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",
        padding:"6px 0",borderBottom:`1px solid ${C.border}20`}}>
        <span style={{fontSize:12,color:C.text}}>{name}</span>
        <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:600,
          background:check.ok?C.green+"15":C.red+"15",
          color:check.ok?C.green:C.red}}>
          {check.status}
        </span>
      </div>
    );
  }

  const overall=data?.overall;
  const overallColor=overall==="ok"?C.green:overall==="degraded"?C.red:C.muted;

  return(
    <div style={{maxWidth:900}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
        <div>
          <div style={{fontSize:18,fontWeight:700,color:C.white||C.textHi}}>System Health</div>
          {lastRun&&<div style={{fontSize:11,color:C.muted,marginTop:2}}>
            Last checked: {lastRun.toLocaleTimeString()}
          </div>}
        </div>
        <div style={{display:"flex",gap:12,alignItems:"center"}}>
          {overall&&(
            <div style={{fontSize:12,fontWeight:700,padding:"6px 14px",borderRadius:8,
              background:overallColor+"15",border:`1px solid ${overallColor}40`,color:overallColor}}>
              {overall==="ok"?"✓ ALL SYSTEMS OK":"⚠ DEGRADED"}
            </div>
          )}
          <Btn onClick={runCheck} disabled={loading} variant="dim" C={C}>
            {loading?"Checking...":"↻ Refresh"}
          </Btn>
        </div>
      </div>

      {loading&&!data&&(
        <div style={{textAlign:"center",padding:48,color:C.muted,fontSize:14}}>Running health checks...</div>
      )}

      {data&&(
        <div style={{display:"grid",gap:12,gridTemplateColumns:"1fr 1fr"}}>
          {/* Left column */}
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            <CheckCard title="Database" check={data.checks?.database}/>
            <CheckCard title="CVE Poll" check={data.checks?.cve_poll}/>
            <CheckCard title="Disk" check={data.checks?.disk}/>
            <CheckCard title="Memory" check={data.checks?.memory}/>
            <CheckCard title="Notifications" check={data.checks?.notifications}/>
            <CheckCard title="Backups" check={data.checks?.backups}/>
          </div>
          {/* Right column */}
          <div style={{display:"flex",flexDirection:"column",gap:12}}>
            {/* API Keys */}
            <div style={{background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:10,padding:"12px 16px"}}>
              <div style={{fontSize:12,fontWeight:700,color:C.white||C.textHi,marginBottom:10}}>
                API Keys ({data.checks?.api_keys?.status})
              </div>
              {data.checks?.api_keys?.services&&Object.entries(data.checks.api_keys.services).map(([svc,info])=>(
                <ApiKeyRow key={svc} svc={svc} info={info}/>
              ))}
            </div>
            {/* Connectivity */}
            <div style={{background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:10,padding:"12px 16px"}}>
              <div style={{fontSize:12,fontWeight:700,color:C.white||C.textHi,marginBottom:10}}>
                External Connectivity
              </div>
              {data.checks?.connectivity&&Object.entries(data.checks.connectivity).map(([name,check])=>(
                <ConnRow key={name} name={name} check={check}/>
              ))}
            </div>
            {/* Access Requests */}
            {data.checks?.access_requests&&(
              <div style={{background:C.surfaceHi,border:`1px solid ${
                (data.checks.access_requests.pending||0)>0?C.amber+"40":C.border}`,
                borderRadius:10,padding:"12px 16px"}}>
                <div style={{display:"flex",justifyContent:"space-between"}}>
                  <div style={{fontSize:12,fontWeight:700,color:C.white||C.textHi}}>Access Requests</div>
                  {data.checks.access_requests.pending>0&&(
                    <span style={{fontSize:11,padding:"2px 8px",borderRadius:4,fontWeight:700,
                      background:C.amber+"15",color:C.amber}}>
                      {data.checks.access_requests.pending} pending
                    </span>
                  )}
                </div>
                <div style={{fontSize:11,color:C.muted,marginTop:4}}>{data.checks.access_requests.status}</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Server-side script tip */}
      <div style={{marginTop:20,padding:"16px 16px",background:C.surfaceHi,
        border:`1px solid ${C.border}`,borderRadius:10}}>
        <div style={{fontSize:12,fontWeight:600,color:C.white||C.textHi,marginBottom:6}}>
          Server-side health check script
        </div>
        <div style={{fontSize:11,color:C.muted,marginBottom:8}}>
          For a deeper server check (systemd, nginx, SSL cert expiry, disk, memory) run directly on the VM:
        </div>
        <code style={{display:"block",fontSize:11,padding:"8px 12px",background:C.surface,
          borderRadius:6,color:C.accentText,fontFamily:"monospace"}}>
          bash /home/ubuntu/threatfeed-repo/scripts/health_check.sh
        </code>
      </div>
    </div>
  );
}

function PasswordChangeCard({token,C}){
  const [cur,setCur]=useState(""); const [nw,setNw]=useState(""); const [conf,setConf]=useState("");
  const [msg,setMsg]=useState(""); const [err,setErr]=useState(""); const [saving,setSaving]=useState(false);
  async function submit(){
    if(!cur||!nw||!conf){setErr("All fields required.");return;}
    if(nw!==conf){setErr("New passwords do not match.");return;}
    if(nw.length<8){setErr("Password must be at least 8 characters.");return;}
    setSaving(true);setErr("");setMsg("");
    const r=await api("/auth/change-password",{method:"POST",
      body:JSON.stringify({current_password:cur,new_password:nw})},token);
    if(r.ok){setMsg("✓ Password changed successfully.");setCur("");setNw("");setConf("");}
    else{const e=await r.json();setErr(e.detail||"Failed to change password.");}
    setSaving(false);
  }
  return(
    <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
      padding:"20px 20px",marginBottom:16,boxShadow:C.shadow}}>
      <div style={{fontSize:13,fontWeight:700,color:C.white||C.textHi,marginBottom:14}}>Change Password</div>
      <div style={{display:"grid",gap:12,maxWidth:360}}>
        {[["Current Password",cur,setCur],["New Password",nw,setNw],["Confirm New Password",conf,setConf]].map(([label,val,set])=>(
          <div key={label}>
            <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4}}>{label}</div>
            <input type="password" value={val} onChange={e=>set(e.target.value)}
              style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                color:C.inputText,padding:"8px 12px",borderRadius:7,fontSize:13,
                outline:"none",fontFamily:"monospace",boxSizing:"border-box"}}/>
          </div>
        ))}
        {err&&<div style={{fontSize:12,color:C.red}}>{err}</div>}
        {msg&&<div style={{fontSize:12,color:C.green}}>{msg}</div>}
        <Btn onClick={submit} disabled={saving} C={C}>{saving?"Saving...":"Change Password"}</Btn>
      </div>
    </div>
  );
}

function CleanupButton({token,C}){
  const [running,setRunning]=useState(false);
  const [result,setResult]=useState("");
  async function run(){
    setRunning(true);setResult("");
    const r=await api("/admin/cleanup-advisory-iocs",{method:"POST"},token);
    if(r.ok){const d=await r.json();setResult(`✓ ${d.message}`);}
    else setResult("✗ Cleanup failed");
    setRunning(false);
  }
  return(
    <div>
      <Btn onClick={run} disabled={running} variant="dim" C={C}>
        {running?"Running...":"🧹 Run Cleanup Now"}
      </Btn>
      {result&&<div style={{marginTop:10,fontSize:12,fontWeight:600,
        color:result.startsWith("✓")?C.green:C.red}}>{result}</div>}
    </div>
  );
}

// At-a-glance state of every key: yours, the platform's shared one, or none.
function KeyStatusList({token,C}){
  const [rows,setRows]=useState(null);
  const load=useCallback(()=>{
    api("/users/me/api-keys",{},token).then(r=>r.ok?r.json():null).then(d=>setRows(d)).catch(()=>setRows(null));
  },[token]);
  useEffect(()=>{
    load();
    window.addEventListener("tfii:keys-changed",load);
    return()=>window.removeEventListener("tfii:keys-changed",load);
  },[load]);
  if(!rows)return null;
  return(
    <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(210px,1fr))",gap:8,marginBottom:14}}>
      {rows.map(k=>{
        const own=k.has_key, plat=!own&&k.source==="platform";
        const col=own?C.green:plat?C.accentText:C.muted;
        return(
          <div key={k.service} data-testid={`key-row-${k.service}`} style={{display:"flex",alignItems:"center",gap:8,padding:"8px 10px",
            background:C.surfaceHi,border:`1px solid ${own?C.green:C.border}`,borderRadius:8}}>
            <span style={{width:8,height:8,borderRadius:"50%",background:col,flexShrink:0}}/>
            <div style={{minWidth:0}}>
              <div style={{fontSize:12,fontWeight:600,color:C.white||C.textHi,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{k.name.split(" (")[0]}</div>
              <div style={{fontSize:10.5,color:col}}>{own?`Your key${k.masked?` · ${k.masked}`:""}`:plat?"Platform key (shared)":"Not set"}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function SettingsPage({token,onLogout,C,me,onOpenApiKeys}){
  const isAdmin = me?.role==="admin";
  const [notifSettings,setNotifSettings]=useState(null);
  const [notifLoading,setNotifLoading]=useState(false);
  const [notifSaving,setNotifSaving]=useState(false);
  const [notifMsg,setNotifMsg]=useState("");
  const [preview,setPreview]=useState(null);
  const [previewLoading,setPreviewLoading]=useState(false);
  const [sending,setSending]=useState(false);
  const [accessRequests,setAccessRequests]=useState([]);
  const [accessLoading,setAccessLoading]=useState(false);
  const [decidingId,setDecidingId]=useState(null);
  const [accessMsg,setAccessMsg]=useState("");

  function loadAccessRequests(){
    setAccessLoading(true);
    api("/admin/access-requests?status=pending",{},token).then(r=>r.ok?r.json():[]).then(d=>{
      setAccessRequests(d||[]);setAccessLoading(false);
    }).catch(()=>setAccessLoading(false));
  }

  useEffect(()=>{ if(isAdmin) loadAccessRequests(); },[isAdmin]);// eslint-disable-line react-hooks/exhaustive-deps

  async function decideRequest(id, action, role){
    setDecidingId(id);setAccessMsg("");
    const r = action==="approve"
      ? await api(`/admin/access-requests/${id}/approve`,{method:"POST",body:JSON.stringify({role:role||"analyst"})},token)
      : await api(`/admin/access-requests/${id}/deny`,{method:"POST"},token);
    if(r.ok){
      const d=await r.json();
      setAccessMsg(action==="approve"
        ? `✓ Approved as ${d.granted_role}${d.email_sent?" — welcome email sent":" — could not send email, configure SMTP in Daily Brief settings below"}`
        : "✓ Request denied");
      loadAccessRequests();
    } else {
      const e=await r.json();setAccessMsg(`✗ ${e.detail||"Failed"}`);
    }
    setDecidingId(null);
    setTimeout(()=>setAccessMsg(""),6000);
  }

  useEffect(()=>{
    if(!isAdmin) return;
    api("/admin/notify/settings",{},token).then(r=>r.ok?r.json():null).then(d=>{
      if(d) setNotifSettings({
        enabled:true, daily_enabled:true, weekly_enabled:true,
        ntfy_topic:"", ntfy_server:"https://ntfy.sh", ntfy_priority:"urgent",
        telegram_token:"", telegram_chat_id:"",
        email_to:"", smtp_host:"", smtp_port:587,
        smtp_user:"", smtp_pass:"", smtp_from:"",
        ...d
      });
    });
  },[token,isAdmin]);// eslint-disable-line react-hooks/exhaustive-deps

  async function saveNotif(){
    setNotifSaving(true);setNotifMsg("");
    const r=await api("/admin/notify/settings",{method:"POST",
      body:JSON.stringify(notifSettings)},token);
    setNotifMsg(r.ok?"✓ Settings saved":"Failed to save settings");
    setTimeout(()=>setNotifMsg(""),3000);
    setNotifSaving(false);
  }

  async function testNotif(){
    setNotifLoading(true);setNotifMsg("");
    const r=await api("/admin/notify/test",{method:"POST"},token);
    if(r.ok) setNotifMsg("✓ Test notification sent — check your device");
    else {const e=await r.json(); setNotifMsg(`✗ ${e.detail||"Failed"}`);}
    setTimeout(()=>setNotifMsg(""),6000);
    setNotifLoading(false);
  }

  async function sendNow(type){
    setSending(type);setNotifMsg("");
    const r=await api(`/admin/notify/send-now?type=${type}`,{method:"POST"},token);
    if(r.ok){const d=await r.json();setNotifMsg(`✓ ${type} brief sent (${d.cves_found} CVEs)`);
    }else{const e=await r.json();setNotifMsg(`✗ ${e.detail||"Failed"}`);}
    setTimeout(()=>setNotifMsg(""),6000);
    setSending(null);
  }

  async function loadPreview(type){
    setPreviewLoading(true);setPreview(null);
    const r=await api(`/admin/notify/preview?type=${type}`,{},token);
    if(r.ok) setPreview(await r.json());
    setPreviewLoading(false);
  }

  function NF({label,field,type="text",placeholder=""}){
    return(
      <div style={{marginBottom:12}}>
        <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4}}>{label}</div>
        <input value={notifSettings?.[field]||""} type={type}
          onChange={e=>setNotifSettings(p=>({...p,[field]:e.target.value}))}
          placeholder={placeholder}
          style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
            color:C.inputText,padding:"8px 12px",borderRadius:7,fontSize:13,
            outline:"none",fontFamily:type==="password"?"monospace":"inherit",
            boxSizing:"border-box"}}/>
      </div>
    );
  }

  return(
    <div style={{maxWidth:700}}>
      {/* API Keys */}
      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
        padding:"20px 20px",marginBottom:16,boxShadow:C.shadow}}>
        <div style={{fontSize:13,fontWeight:700,color:C.white||C.textHi,marginBottom:8}}>
          API Keys
        </div>
        <div style={{fontSize:12,color:C.muted,marginBottom:12}}>
          Add personal keys for VirusTotal, AbuseIPDB, Shodan, Groq, NVD, abuse.ch and OTX.
        </div>
        <KeyStatusList token={token} C={C}/>
        <Btn onClick={onOpenApiKeys} C={C}>Manage API Keys</Btn>
      </div>

      {/* Change Password */}
      <PasswordChangeCard token={token} C={C}/>

      {/* ── ADMIN: IOC Feed Cleanup ── */}
      {isAdmin&&(
        <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
          padding:"20px 20px",marginBottom:16,boxShadow:C.shadow}}>
          <div style={{fontSize:13,fontWeight:700,color:C.white||C.textHi,marginBottom:4}}>
            🧹 IOC Feed Cleanup
          </div>
          <div style={{fontSize:11,color:C.muted,marginBottom:14,lineHeight:1.6}}>
            Removes false-positive IOCs that were auto-added from CVE references —
            vendor advisory URLs, Google, CISA, GitHub, and other trusted domains
            that should never have been in the feed. Safe to run multiple times.
          </div>
          <CleanupButton token={token} C={C}/>
        </div>
      )}

      {/* ── ADMIN: Access Requests ── */}
      {isAdmin&&(
        <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
          padding:"20px 20px",marginBottom:16,boxShadow:C.shadow}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}>
            <div>
              <div style={{fontSize:13,fontWeight:700,color:C.white||C.textHi,marginBottom:2}}>
                🔓 Access Requests {accessRequests.length>0&&`(${accessRequests.length})`}
              </div>
              <div style={{fontSize:11,color:C.muted}}>
                Explorer/demo users requesting full access to the IOC Feed, CVE Monitor, and Campaigns
              </div>
            </div>
            <button onClick={loadAccessRequests}
              style={{fontSize:11,padding:"4px 12px",borderRadius:6,background:C.surfaceHi,
                border:`1px solid ${C.border}`,color:C.muted,cursor:"pointer",fontFamily:"inherit"}}>
              {accessLoading?"...":"↻ Refresh"}
            </button>
          </div>

          {accessRequests.length===0?(
            <div style={{fontSize:12,color:C.muted,padding:"12px 0",textAlign:"center"}}>
              No pending requests.
            </div>
          ):(
            <div style={{display:"flex",flexDirection:"column",gap:8}}>
              {accessRequests.map(req=>(
                <div key={req.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",
                  flexWrap:"wrap",gap:12,padding:"12px 16px",background:C.surfaceHi,
                  border:`1px solid ${C.border}`,borderRadius:9}}>
                  <div style={{minWidth:0}}>
                    <div style={{fontSize:13,fontWeight:600,color:C.white||C.textHi}}>{req.username}</div>
                    <div style={{fontSize:11,color:C.muted}}>{req.email}</div>
                    {req.message&&<div style={{fontSize:11,color:C.text,marginTop:4,fontStyle:"italic"}}>"{req.message}"</div>}
                    <div style={{fontSize:10,color:C.muted,marginTop:2}}>
                      Requested {new Date(req.requested_at).toLocaleDateString()}
                    </div>
                  </div>
                  <div style={{display:"flex",gap:8,flexShrink:0}}>
                    <button onClick={()=>decideRequest(req.id,"approve","analyst")} disabled={decidingId===req.id}
                      style={{fontSize:11,padding:"6px 12px",borderRadius:6,cursor:"pointer",
                        background:C.green+"15",border:`1px solid ${C.green}40`,color:C.green,
                        fontWeight:600,fontFamily:"inherit"}}>
                      {decidingId===req.id?"...":"✓ Approve"}
                    </button>
                    <button onClick={()=>decideRequest(req.id,"deny")} disabled={decidingId===req.id}
                      style={{fontSize:11,padding:"6px 12px",borderRadius:6,cursor:"pointer",
                        background:C.surface,border:`1px solid ${C.border}`,color:C.muted,
                        fontWeight:600,fontFamily:"inherit"}}>
                      Deny
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
          {accessMsg&&(
            <div style={{marginTop:10,fontSize:12,fontWeight:600,
              color:accessMsg.startsWith("✓")?C.green:C.red}}>{accessMsg}</div>
          )}
          <div style={{fontSize:10,color:C.muted,marginTop:10}}>
            Approval emails reuse the SMTP settings configured below in Admin Notifications.
          </div>
        </div>
      )}

      {/* ── ADMIN: Notification Center ── */}
      {isAdmin&&notifSettings&&(
        <div style={{background:C.surface,border:`1px solid ${C.accent}30`,borderRadius:12,
          padding:"20px 20px",marginBottom:16,boxShadow:C.shadow}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:16}}>
            <div>
              <div style={{fontSize:13,fontWeight:700,color:C.white||C.textHi,marginBottom:2}}>
                🔔 Admin Notifications
              </div>
              <div style={{fontSize:11,color:C.muted}}>
                Daily CVE digest → your phone/email
              </div>
            </div>
            <label style={{display:"flex",alignItems:"center",gap:8,cursor:"pointer"}}>
              <span style={{fontSize:12,color:C.muted}}>Enabled</span>
              <input type="checkbox" checked={notifSettings.enabled||false}
                onChange={e=>setNotifSettings(p=>({...p,enabled:e.target.checked}))}
                style={{accentColor:C.accent,width:16,height:16}}/>
            </label>
          </div>

          {/* Schedule toggles */}
          <div style={{display:"flex",gap:12,marginBottom:18}}>
            {[["daily_enabled","📅 Daily Brief (8 AM)"],["weekly_enabled","📊 Weekly Summary (Sunday)"]].map(([k,label])=>(
              <label key={k} style={{display:"flex",alignItems:"center",gap:8,cursor:"pointer",
                padding:"7px 14px",background:notifSettings[k]?C.accentDim:C.surfaceHi,
                border:`1px solid ${notifSettings[k]?C.accent:C.border}`,
                borderRadius:8,fontSize:12,fontWeight:600,
                color:notifSettings[k]?C.accentText:C.muted}}>
                <input type="checkbox" checked={notifSettings[k]||false}
                  onChange={e=>setNotifSettings(p=>({...p,[k]:e.target.checked}))}
                  style={{accentColor:C.accent}}/>
                {label}
              </label>
            ))}
          </div>

          {/* Channel sections */}
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))",gap:16,marginBottom:16}}>

            {/* ntfy.sh */}
            <div style={{padding:"16px 16px",background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:10}}>
              <div style={{fontSize:12,fontWeight:700,color:C.white||C.textHi,marginBottom:2}}>
                📱 ntfy (Push Notifications)
              </div>
              <div style={{fontSize:10,color:C.muted,marginBottom:10,lineHeight:1.6}}>
                Free push to Android/iOS. Works with ntfy.sh or your own server.{" "}
                <a href="https://ntfy.sh" target="_blank" rel="noreferrer" style={{color:C.accentText}}>ntfy.sh →</a>
              </div>

              <NF label="Topic name (keep this secret)" field="ntfy_topic" placeholder="my-secret-tfii-alerts"/>

              <div style={{marginBottom:12}}>
                <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4}}>Server</div>
                <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:6}}>
                  {[["https://ntfy.sh","ntfy.sh (public)"],["custom","Self-hosted"]].map(([val,label])=>(
                    <button key={val} onClick={()=>setNotifSettings(p=>({...p,
                      ntfy_server:val==="custom"?(p.ntfy_server==="https://ntfy.sh"?"https://your-ntfy-server.com":p.ntfy_server):val}))}
                      style={{padding:"4px 12px",borderRadius:6,border:`1px solid ${
                        (notifSettings.ntfy_server||"https://ntfy.sh")===(val==="custom"?"https://ntfy.sh":val)?C.border:C.accent}`,
                        background:(notifSettings.ntfy_server||"https://ntfy.sh")===(val==="custom"?"https://ntfy.sh":val)?C.surfaceHi:C.accentDim,
                        color:(notifSettings.ntfy_server||"https://ntfy.sh")===(val==="custom"?"https://ntfy.sh":val)?C.muted:C.accentText,
                        fontSize:11,cursor:"pointer",fontFamily:"inherit",fontWeight:600}}>
                      {label}
                    </button>
                  ))}
                </div>
                <input value={notifSettings?.ntfy_server||"https://ntfy.sh"}
                  onChange={e=>setNotifSettings(p=>({...p,ntfy_server:e.target.value}))}
                  placeholder="https://ntfy.sh"
                  style={{width:"100%",background:C.inputBg,border:`1px solid ${C.inputBorder}`,
                    color:C.inputText,padding:"8px 12px",borderRadius:7,fontSize:12,
                    outline:"none",fontFamily:"monospace",boxSizing:"border-box"}}/>
              </div>

              <div style={{marginBottom:12}}>
                <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:4}}>
                  Priority
                  <span style={{marginLeft:6,fontWeight:400,color:C.muted,fontSize:10}}>
                    — urgent bypasses Android Doze via FCM
                  </span>
                </div>
                <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
                  {[["min","Min"],["low","Low"],["default","Default"],["high","High"],["urgent","Urgent ⚡"]].map(([val,label])=>(
                    <button key={val}
                      onClick={()=>setNotifSettings(p=>({...p,ntfy_priority:val}))}
                      style={{padding:"4px 12px",borderRadius:6,border:`1px solid ${
                        (notifSettings.ntfy_priority||"urgent")===val?C.accent:C.border}`,
                        background:(notifSettings.ntfy_priority||"urgent")===val?C.accentDim:C.surfaceHi,
                        color:(notifSettings.ntfy_priority||"urgent")===val?C.accentText:C.muted,
                        fontSize:11,cursor:"pointer",fontFamily:"inherit",fontWeight:600}}>
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Doze mode instructions */}
              <div style={{padding:"12px 12px",background:C.accentDim,border:`1px solid ${C.accent}30`,
                borderRadius:8,fontSize:10,color:C.accentText,lineHeight:1.8}}>
                <div style={{fontWeight:700,marginBottom:4}}>📲 Android Doze Mode Setup</div>
                <div style={{color:C.text}}>
                  <b>Option 1 — ntfy.sh or self-hosted with FCM:</b><br/>
                  Set priority to <b>Urgent</b> above → notifications delivered via FCM,
                  bypasses Doze automatically. No extra app config needed.<br/><br/>
                  <b>Option 2 — Self-hosted without FCM:</b><br/>
                  In the ntfy Android app → <b>Settings → General → Enable "Instant delivery"</b>.
                  This keeps a persistent WebSocket connection.
                  Then in Android → Battery → find ntfy → set to <b>"Unrestricted"</b>.
                </div>
              </div>
            </div>

            {/* Telegram */}
            <div style={{padding:"16px 16px",background:C.surfaceHi,border:`1px solid ${C.border}`,borderRadius:10}}>
              <div style={{fontSize:12,fontWeight:700,color:C.white||C.textHi,marginBottom:2}}>
                ✈️ Telegram Bot
              </div>
              <div style={{fontSize:10,color:C.muted,marginBottom:10,lineHeight:1.5}}>
                Create a bot via @BotFather → get token. Message the bot to get your Chat ID.
              </div>
              <NF label="Bot Token" field="telegram_token" type="password" placeholder="1234567890:ABCdef..."/>
              <NF label="Chat ID" field="telegram_chat_id" placeholder="Your Telegram chat ID"/>
            </div>
          </div>

          {/* Email */}
          <details style={{marginBottom:16}}>
            <summary style={{fontSize:12,fontWeight:600,color:C.muted,cursor:"pointer",marginBottom:8}}>
              📧 Email (SMTP) — expand to configure
            </summary>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginTop:10}}>
              <NF label="Recipient Email" field="email_to" placeholder="you@email.com"/>
              <NF label="SMTP Host" field="smtp_host" placeholder="smtp.gmail.com"/>
              <NF label="SMTP Port" field="smtp_port" placeholder="587"/>
              <NF label="SMTP User" field="smtp_user" placeholder="your@gmail.com"/>
              <NF label="SMTP Password" field="smtp_pass" type="password" placeholder="App password"/>
              <NF label="From Address" field="smtp_from" placeholder="TFII Alerts <you@email.com>"/>
            </div>
          </details>

          {/* Actions */}
          <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
            <Btn onClick={saveNotif} disabled={notifSaving} C={C}>
              {notifSaving?"Saving...":"💾 Save Settings"}
            </Btn>
            <Btn onClick={testNotif} disabled={notifLoading} variant="dim" C={C}>
              {notifLoading?"Sending...":"🧪 Send Test"}
            </Btn>
            <Btn onClick={()=>sendNow("daily")} disabled={!!sending} variant="dim" C={C}>
              {sending==="daily"?"Sending...":"📅 Send Daily Now"}
            </Btn>
            <Btn onClick={()=>sendNow("weekly")} disabled={!!sending} variant="dim" C={C}>
              {sending==="weekly"?"Sending...":"📊 Send Weekly Now"}
            </Btn>
            <Btn onClick={()=>loadPreview("daily")} disabled={previewLoading} variant="dim" C={C}>
              {previewLoading?"Loading...":"👁 Preview Brief"}
            </Btn>
          </div>
          {notifMsg&&(
            <div style={{marginTop:10,fontSize:12,fontWeight:600,
              color:notifMsg.startsWith("✓")?C.green:C.red}}>
              {notifMsg}
            </div>
          )}

          {/* Preview panel */}
          {preview&&(
            <div style={{marginTop:16,padding:"16px 16px",background:C.surfaceHi,
              border:`1px solid ${C.border}`,borderRadius:10}}>
              <div style={{display:"flex",justifyContent:"space-between",marginBottom:8}}>
                <div style={{fontSize:11,fontWeight:700,color:C.accentText,textTransform:"uppercase"}}>
                  Brief Preview
                </div>
                <button onClick={()=>setPreview(null)}
                  style={{background:"none",border:"none",color:C.muted,cursor:"pointer",fontSize:16}}>×</button>
              </div>
              <pre style={{margin:0,fontSize:11,color:C.text,lineHeight:1.7,
                whiteSpace:"pre-wrap",fontFamily:"monospace",maxHeight:400,overflowY:"auto"}}>
                {preview.body}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Logout */}
      <div style={{background:C.surface,border:`1px solid ${C.border}`,borderRadius:12,
        padding:"20px 20px",boxShadow:C.shadow}}>
        <Btn onClick={onLogout} variant="danger" C={C}>Sign Out</Btn>
      </div>
    </div>
  );
}

// ── MAIN APP ──────────────────────────────────────────────────────────────────

// The original single-page shell (sidebar, IOC/CVE mode switch, inline IOC
// feed/add/import/export/users/invites views) was replaced by the redesigned
// app in ../Root.js; those inline views were ported to ../pages. Everything
// below is the reusable surface the new shell renders.
export {
  api,
  NavIcon,
  TLPBadge,
  SevBadge,
  Btn,
  Card,
  Field,
  Inp,
  SlowLoader,
  CVEDetail,
  CVEReportModal,
  BulkLookup,
  DemoLockedPage,
  PublicSearch,
  AssetManager,
  GeoMap,
  CVELookup,
  OSINTTool,
  URLDecoder,
  SafeLinkExtractor,
  UserAgentParser,
  RedirectTracer,
  PermissionsPanel,
  FilesPage,
  DiffChecker,
  QueryGenerator,
  ApiKeyModal,
  WorkspacePage,
  AdvisoryBuilder,
  HealthPage,
  SettingsPage,
};
