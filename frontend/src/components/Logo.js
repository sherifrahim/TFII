import React, { useId } from "react";

// The TFII mark: a faceted shield (protection) holding a "T" (the platform) and one lit
// indicator (the thing it watches for). The outline draws itself on first paint, the dot
// pulses while live, and the whole mark reacts to hover. Pure SVG: no assets to load.
export function Logo({ size = 28, animate = false, live = true, spin = false, className = "", title }) {
  const id = useId().replace(/:/g, "");
  return (
    <svg className={`logo ${animate ? "animate" : ""} ${live ? "live" : ""} ${spin ? "spin" : ""} ${className}`} width={size} height={size} viewBox="0 0 32 32"
      role={title ? "img" : undefined} aria-hidden={title ? undefined : true} aria-label={title}>
      {title && <title>{title}</title>}
      <defs>
        <linearGradient id={`${id}g`} x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#5EEAD4" /><stop offset=".55" stopColor="#7AA2FF" /><stop offset="1" stopColor="#A78BFA" />
        </linearGradient>
        <linearGradient id={`${id}f`} x1="16" y1="3" x2="16" y2="29" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#5EEAD4" stopOpacity=".2" /><stop offset="1" stopColor="#A78BFA" stopOpacity=".05" />
        </linearGradient>
      </defs>
      <path className="l-shield" pathLength="100" d="M16 2.9l10.1 3.8v8.5c0 6.1-4.2 10.7-10.1 12.9C10.1 25.9 5.9 21.3 5.9 15.2V6.7z"
        fill={`url(#${id}f)`} stroke={`url(#${id}g)`} strokeWidth="1.7" strokeLinejoin="round" />
      <g className="l-t" fill={`url(#${id}g)`}>
        <rect x="10.4" y="10.2" width="11.2" height="2.6" rx="1.3" />
        <rect x="14.7" y="10.2" width="2.6" height="11.2" rx="1.3" />
      </g>
      <circle className="l-ring" cx="22.4" cy="21.4" r="2" fill="none" stroke="#5EEAD4" strokeWidth="1" />
      <circle className="l-dot" cx="22.4" cy="21.4" r="1.7" fill="#5EEAD4" />
    </svg>
  );
}

export function Wordmark({ size = 15 }) {
  return <span className="sb-name" style={{ fontSize: size }}>TF<b>II</b></span>;
}

export default Logo;
