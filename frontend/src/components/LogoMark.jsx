import { useId } from 'react';

/* PrivacyPilot brand mark: the navigator shield.
   A shield (protection) holding a compass needle (the "pilot" that steers
   you to DPDP compliance). Same artwork as public/logo-mark.svg. */
export default function LogoMark({ size = 32, title }) {
  const g = `pp-g-${useId().replace(/:/g, '')}`;
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg"
      role={title ? 'img' : undefined} aria-label={title} aria-hidden={title ? undefined : true}>
      <defs>
        <linearGradient id={g} x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#34d399" />
          <stop offset="1" stopColor="#047857" />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="16" fill={`url(#${g})`} />
      <path d="M32 9.5 L50.5 16.2 V30.5 C50.5 42.6 42.8 51 32 54.5 C21.2 51 13.5 42.6 13.5 30.5 V16.2 Z" fill="#fff" />
      <g transform="rotate(40 32 31.5)">
        <path d="M32 17.5 L37 31.5 H27 Z" fill="#065f46" />
        <path d="M32 45.5 L37 31.5 H27 Z" fill="#6ee7b7" />
      </g>
      <circle cx="32" cy="31.5" r="2" fill="#fff" />
    </svg>
  );
}
