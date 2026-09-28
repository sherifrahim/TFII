// Palette tokens. `LEGACY_C` maps the TFII design system onto the token names
// the original component library expects (bg, surface, accent, …), so every
// legacy tool renders in the new visual language without being rewritten.

export const T = {
  bg: "#08090B",
  surface: "#0D0F12",
  elevated: "#12151A",
  elevated2: "#171B21",
  border: "#1D2229",
  borderStrong: "#2A313A",
  gold: "#D7A83D",
  goldHi: "#F0C75E",
  critical: "#F04444",
  high: "#F59E0B",
  medium: "#3B82F6",
  low: "#6B7280",
  success: "#22C55E",
  violet: "#A78BFA",
  text: "#F5F7FA",
  text2: "#C4C9D1",
  text3: "#8B929D",
  text4: "#5E6570",
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

// Categorical colours for IOC types / graph node kinds. Deliberately not gold,
// which is reserved for brand, primary actions and selection.
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
  campaign: "#F59E0B",
  actor: "#F04444",
  malware: "#F472B6",
  cve: "#F87171",
  investigation: "#D7A83D",
  observable: "#94A3B8",
  asset: "#34D399",
};

export const LEGACY_C = {
  name: "TFII",
  font: "'Inter',-apple-system,BlinkMacSystemFont,sans-serif",
  bg: T.bg, surface: T.surface, surfaceHi: T.elevated,
  border: T.border, borderHi: T.borderStrong,
  // Legacy components put white text on `accent`, so they get the deeper end of
  // the gold ramp for contrast; `accentText` is the bright brand gold.
  accent: "#A87F22", accentDim: "rgba(215,168,61,0.10)", accentText: T.goldHi, accentHover: T.gold,
  text: T.text2, textHi: T.text, muted: T.text3, mutedHi: "#A3AAB4",
  white: T.text, green: T.success, amber: T.high, red: T.critical, purple: T.violet, blue: T.medium,
  inputBg: T.surface, inputBorder: T.border, inputText: T.text,
  shadow: "none",
  shadowMd: "0 12px 32px -12px rgba(0,0,0,.7)",
  badge: T.elevated, navActive: "rgba(215,168,61,0.10)", navActiveBorder: T.gold,
  statNum: T.text, statLabel: T.gold,
  sidebarBg: "#0A0B0E", topbarBg: "rgba(8,9,11,.9)",
  glass: false,
};
