export default function ScoreRing({ score, color = '#6366f1', size = 160 }) {
  const r = 58;
  const circ = 2 * Math.PI * r;
  const fill = Math.min(100, Math.max(0, score));
  const dashArray = `${(fill / 100) * circ} ${circ}`;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 136 136"
      style={{ display: 'block' }}
    >
      {/* Track */}
      <circle
        cx="68" cy="68" r={r}
        fill="none"
        stroke="#e2e8f0"
        strokeWidth="11"
      />
      {/* Progress */}
      <circle
        cx="68" cy="68" r={r}
        fill="none"
        stroke={color}
        strokeWidth="11"
        strokeLinecap="round"
        strokeDasharray={dashArray}
        strokeDashoffset="0"
        transform="rotate(-90 68 68)"
        style={{ transition: 'stroke-dasharray 1.2s cubic-bezier(0.4,0,0.2,1)' }}
      />
      {/* Score number */}
      <text
        x="68" y="63"
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize="32"
        fontWeight="800"
        fontFamily="Inter, system-ui, sans-serif"
        fill={color}
      >
        {score}
      </text>
      {/* /100 label */}
      <text
        x="68" y="85"
        textAnchor="middle"
        fontSize="11"
        fontFamily="Inter, system-ui, sans-serif"
        fill="#94a3b8"
        fontWeight="500"
      >
        / 100
      </text>
    </svg>
  );
}
