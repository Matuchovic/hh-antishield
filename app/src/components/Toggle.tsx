/** Přepínač (role switch). Popis je součástí tlačítka kvůli přístupnosti. */
export function Toggle({
  checked,
  onChange,
  label,
  detail,
  disabled = false,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  detail?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      className={`toggle-row${checked ? " is-on" : ""}`}
      disabled={disabled}
      onClick={() => onChange(!checked)}
    >
      <span className="toggle-text">
        <span className="toggle-label">{label}</span>
        {detail ? <span className="toggle-detail">{detail}</span> : null}
      </span>
      <span className="switch" aria-hidden="true" />
    </button>
  );
}
