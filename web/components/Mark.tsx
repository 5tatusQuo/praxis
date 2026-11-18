// The Praxis lens: two hexagonal goggle lenses joined by a bridge. The left
// lens is theory (a faint grid); the right is practice (one cell lit, under a
// reticle).
export function Mark({ size = 28 }: { size?: number }) {
  const hex = "13,2 23,7.5 23,18.5 13,24 3,18.5 3,7.5";
  return (
    <svg width={size * 2} height={size} viewBox="0 0 56 26" role="img" aria-label="PRAXIS">
      <polygon points={hex} fill="none" stroke="#C9D1D9" strokeWidth="1.6" />
      <g fill="#C9D1D9" opacity="0.35">
        <rect x="8" y="8" width="3" height="3" />
        <rect x="12" y="8" width="3" height="3" />
        <rect x="16" y="8" width="3" height="3" />
        <rect x="8" y="12" width="3" height="3" />
        <rect x="12" y="12" width="3" height="3" />
        <rect x="16" y="12" width="3" height="3" />
        <rect x="10" y="16" width="3" height="3" />
        <rect x="14" y="16" width="3" height="3" />
      </g>
      <line x1="23" y1="13" x2="33" y2="13" stroke="#C9D1D9" strokeWidth="1.6" />
      <g transform="translate(30 0)">
        <polygon points={hex} fill="none" stroke="#D4A24C" strokeWidth="1.6" />
        <g fill="#C9D1D9" opacity="0.35">
          <rect x="8" y="8" width="3" height="3" />
          <rect x="16" y="8" width="3" height="3" />
          <rect x="8" y="12" width="3" height="3" />
          <rect x="16" y="12" width="3" height="3" />
          <rect x="10" y="16" width="3" height="3" />
          <rect x="14" y="16" width="3" height="3" />
        </g>
        <rect x="11.5" y="9.5" width="3" height="3" fill="#D4A24C" />
        <circle cx="13" cy="11" r="4.2" fill="none" stroke="#D4A24C" strokeWidth="0.9" />
        <path d="M13 5.2v2.2M13 14.6v2.2M7.2 11h2.2M16.6 11h2.2" stroke="#D4A24C" strokeWidth="0.9" />
      </g>
    </svg>
  );
}
