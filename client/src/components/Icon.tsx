/** Inline SVG icon set (stroke icons, 24px grid) - no icon font, no network. */
const PATHS: Record<string, string> = {
  shield: 'M12 3l7 3v5c0 4.6-3 8.6-7 10-4-1.4-7-5.4-7-10V6z',
  shieldCheck: 'M12 3l7 3v5c0 4.6-3 8.6-7 10-4-1.4-7-5.4-7-10V6z M9 12l2 2 4-4',
  shieldAlert: 'M12 3l7 3v5c0 4.6-3 8.6-7 10-4-1.4-7-5.4-7-10V6z M12 8v4 M12 16h.01',
  lock: 'M6 11h12v9H6z M8.5 11V8a3.5 3.5 0 017 0v3',
  unlock: 'M6 11h12v9H6z M8.5 11V8a3.5 3.5 0 016.8-1.2',
  key: 'M14.5 9.5a4 4 0 11-5.6 3.7L3 19.1V21h2.5v-1.5H7V18h1.5l1.4-1.4A4 4 0 0114.5 9.5z M16 8h.01',
  link: 'M10 14a4.5 4.5 0 006.4 0l3-3a4.5 4.5 0 00-6.4-6.4l-1 1 M14 10a4.5 4.5 0 00-6.4 0l-3 3a4.5 4.5 0 006.4 6.4l1-1',
  users: 'M16 20v-1.5a3.5 3.5 0 00-3.5-3.5h-5A3.5 3.5 0 004 18.5V20 M10 11a3.5 3.5 0 100-7 3.5 3.5 0 000 7z M20 20v-1.5a3.5 3.5 0 00-2.5-3.35 M15.5 4.2a3.5 3.5 0 010 6.6',
  user: 'M18 20v-1.5a4 4 0 00-4-4h-4a4 4 0 00-4 4V20 M12 11a4 4 0 100-8 4 4 0 000 8z',
  file: 'M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z M14 3v5h5',
  qr: 'M4 4h6v6H4z M14 4h6v6h-6z M4 14h6v6H4z M14 14h2v2h-2z M18 14h2 M14 18h2 M18 18h2v2 M17 17h1',
  chat: 'M20 15a2 2 0 01-2 2H8l-4 4V6a2 2 0 012-2h12a2 2 0 012 2z',
  flask: 'M9 3h6 M10 3v6l-5.5 9.5A1.7 1.7 0 006 21h12a1.7 1.7 0 001.5-2.5L14 9V3 M7.5 15h9',
  device: 'M7 3h10a1 1 0 011 1v16a1 1 0 01-1 1H7a1 1 0 01-1-1V4a1 1 0 011-1z M11 18h2',
  plus: 'M12 5v14 M5 12h14',
  send: 'M4 12l16-8-6 16-2.5-6.5z M11.5 13.5L20 4',
  paperclip: 'M20 11.5l-7.8 7.8a5 5 0 01-7.1-7.1l8.5-8.5a3.3 3.3 0 014.7 4.7l-8.5 8.5a1.7 1.7 0 01-2.4-2.4l7.8-7.8',
  eye: 'M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z M12 15a3 3 0 100-6 3 3 0 000 6z',
  x: 'M6 6l12 12 M18 6L6 18',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  checks: 'M2 12.5l4.5 4.5L16 7.5 M11 16l1 1 9.5-9.5',
  timer: 'M12 21a8 8 0 100-16 8 8 0 000 16z M12 9v4l2.5 2.5 M9.5 2h5',
  rotate: 'M20 11a8 8 0 00-14.4-4.8L4 8 M4 4v4h4 M4 13a8 8 0 0014.4 4.8L20 16 M20 20v-4h-4',
  download: 'M12 4v11 M7 10.5l5 5 5-5 M5 20h14',
  upload: 'M12 20V9 M7 13.5l5-5 5 5 M5 4h14',
  copy: 'M9 9h10v11H9z M5 15V4h10',
  trash: 'M4 7h16 M9 7V4h6v3 M6 7l1 13h10l1-13',
  alert: 'M12 3l9.5 17h-19z M12 10v4 M12 17h.01',
  info: 'M12 21a9 9 0 100-18 9 9 0 000 18z M12 11v5 M12 8h.01',
  menu: 'M4 7h16 M4 12h16 M4 17h16',
  back: 'M15 5l-7 7 7 7',
  zap: 'M13 2L4 14h7l-1 8 9-12h-7z',
  cpu: 'M7 7h10v10H7z M10 10h4v4h-4z M9 3v3 M15 3v3 M9 18v3 M15 18v3 M3 9h3 M3 15h3 M18 9h3 M18 15h3',
  server: 'M4 4h16v6H4z M4 14h16v6H4z M8 7h.01 M8 17h.01',
  image: 'M4 5h16v14H4z M4 16l5-5 4 4 2-2 5 5 M15 9h.01',
  logout: 'M15 4h4v16h-4 M10 16l-4-4 4-4 M6 12h10',
  scan: 'M4 8V5a1 1 0 011-1h3 M16 4h3a1 1 0 011 1v3 M20 16v3a1 1 0 01-1 1h-3 M8 20H5a1 1 0 01-1-1v-3 M7 12h10',
  sparkle: 'M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z',
  hash: 'M5 9h14 M5 15h14 M10 4L8 20 M16 4l-2 16',
};

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 18, className, title }: { name: IconName; size?: number; className?: string; title?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden={title ? undefined : true}
      role={title ? 'img' : undefined}
    >
      {title && <title>{title}</title>}
      <path d={PATHS[name]} />
    </svg>
  );
}

export function Logo({ size = 38 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden>
      <rect width="64" height="64" rx="14" fill="#10151c" stroke="#1f2835" />
      <path d="M32 10l18 7v13c0 11.5-7.6 20.6-18 24-10.4-3.4-18-12.5-18-24V17z" fill="none" stroke="#5eead4" strokeWidth="4" strokeLinejoin="round" />
      <rect x="24" y="29" width="16" height="12" rx="2.5" fill="#5eead4" />
      <path d="M27 29v-4a5 5 0 0110 0v4" fill="none" stroke="#5eead4" strokeWidth="3.5" />
    </svg>
  );
}
