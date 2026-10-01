// Palette tokens. `LEGACY_C` maps the TFII design system onto the token names
// the original component library expects (bg, surface, accent, …), so every
// legacy tool renders in the new visual language without being rewritten.

export const T = {
  bg: "#05060A",
  surface: "#0A0C12",
  elevated: "#10131B",
  elevated2: "#161A24",
  border: "#1B202B",
  borderStrong: "#2A3040",
  accent: "#5EEAD4",
  accentHi: "#A5F3E6",
  accent2: "#7AA2FF",
  accent3: "#A78BFA",
  critical: "#FF5C6C",
  high: "#FFB020",
  medium: "#5B9BFF",
  low: "#8892A6",
  success: "#3DDC97",
  violet: "#A78BFA",
  text: "#F3F6FB",
  text2: "#C7CEDB",
  text3: "#8C95A8",
  text4: "#5E687C",
};

export const SEV_COLOR = {
  critical: T.critical,
  high: T.high,
  medium: T.medium,
  low: T.low,
  none: T.low,
  success: T.success,
  info: T.text3,
};

// Categorical colours for IOC types / graph node kinds. Deliberately not the
// accent, which is reserved for brand, primary actions and selection.
export const TYPE_COLOR = {
  IPv4: "#38BDF8", IPv6: "#38BDF8",
  Domain: "#A78BFA",
  URL: "#F472B6",
  MD5: "#34D399", SHA1: "#34D399", SHA256: "#34D399",
  Email: "#FB923C",
  CVE: "#F87171",
  Filename: "#94A3B8",
};

export const KIND_COLOR = {
  ioc: "#38BDF8",
  campaign: "#FFB020",
  actor: "#FF5C6C",
  malware: "#F472B6",
  cve: "#F87171",
  investigation: "#5EEAD4",
  observable: "#94A3B8",
  asset: "#34D399",
};

// Maps the design system onto the token names the original component library
// expects (bg, surface, accent, ...), so every older tool renders in the new
// visual language without being rewritten. Hex only: those components append
// alpha digits ("#rrggbb" + "15").
export const LEGACY_C = {
  name: "TFII",
  font: "'Inter Variable','Inter',-apple-system,BlinkMacSystemFont,sans-serif",
  bg: T.bg, surface: T.surface, surfaceHi: T.elevated,
  border: T.border, borderHi: T.borderStrong,
  // Older components put white text on `accent`, so they get the deeper teal for
  // contrast; `accentText` is the bright brand colour for text on dark.
  accent: "#0D9488", accentDim: "rgba(94,234,212,0.10)", accentText: T.accent, accentHover: "#14B8A6",
  text: T.text2, textHi: T.text, muted: T.text3, mutedHi: "#A9B1C2",
  white: T.text, green: T.success, amber: T.high, red: T.critical, purple: T.violet, blue: T.medium,
  inputBg: T.surface, inputBorder: T.border, inputText: T.text,
  shadow: "none",
  shadowMd: "0 18px 44px -14px rgba(0,0,0,.75)",
  badge: T.elevated, navActive: "rgba(94,234,212,0.10)", navActiveBorder: T.accent,
  statNum: T.text, statLabel: T.accent,
  sidebarBg: "#07080D", topbarBg: "rgba(5,6,10,.8)",
  glass: false,
};
