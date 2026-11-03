import { useState, type ReactNode } from "react";

export function CopyButton({
  value,
  label = "Copy",
  onCopied,
  className = "",
}: {
  value: string;
  label?: string;
  onCopied?: (message: string) => void;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
      onCopied?.("Copied to clipboard");
    } catch {
      

      const area = document.createElement("textarea");
      area.value = value;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand("copy");
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1200);
        onCopied?.("Copied to clipboard");
      } catch {
        onCopied?.("Clipboard access was denied");
      } finally {
        document.body.removeChild(area);
      }
    }
  };

  return (
    <button type="button" className={`copy-button ${className}`} onClick={copy} title={label}>
      {copied ? "Copied" : label}
    </button>
  );
}

export function Field({
  label,
  value,
  copy,
  onCopied,
  mono = false,
}: {
  label: string;
  value: ReactNode;
  copy?: string;
  onCopied?: (message: string) => void;
  mono?: boolean;
}) {
  return (
    <div className="field">
      <div className="field-label">{label}</div>
      <div className={`field-value ${mono ? "mono" : ""}`}>
        {value ?? "—"}
        {copy !== undefined && (
          <CopyButton value={copy} label="copy" onCopied={onCopied} className="inline-copy" />
        )}
      </div>
    </div>
  );
}

export function SearchInput({
  value,
  onChange,
  placeholder = "Filter…",
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  return (
    <input
      className="search-input"
      type="search"
      value={value}
      placeholder={placeholder}
      onChange={(event) => onChange(event.target.value)}
      spellCheck={false}
    />
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty-state">
      <div className="empty-title">{title}</div>
      {children && <div className="empty-body">{children}</div>}
    </div>
  );
}

export function SectionCard({
  title,
  extra,
  children,
  className = "",
}: {
  title: string;
  extra?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      <header className="card-head">
        <h3>{title}</h3>
        {extra && <div className="card-extra">{extra}</div>}
      </header>
      <div className="card-body">{children}</div>
    </section>
  );
}

export function Badge({
  children,
  tone = "neutral",
  title,
}: {
  children: ReactNode;
  tone?: string;
  title?: string;
}) {
  return (
    <span className={`badge badge-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function Pager({
  page,
  pageCount,
  total,
  onChange,
}: {
  page: number;
  pageCount: number;
  total: number;
  onChange: (page: number) => void;
}) {
  return (
    <div className="pager">
      <button type="button" className="ghost" disabled={page <= 0} onClick={() => onChange(page - 1)}>
        Previous
      </button>
      <span>
        Page {pageCount === 0 ? 0 : page + 1} of {Math.max(pageCount, 1)} · {total.toLocaleString()} rows
      </span>
      <button
        type="button"
        className="ghost"
        disabled={page + 1 >= pageCount}
        onClick={() => onChange(page + 1)}
      >
        Next
      </button>
    </div>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  hint,
  disabled,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  hint?: string;
  disabled?: boolean;
}) {
  return (
    <label className={`toggle ${disabled ? "disabled" : ""}`}>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span>
        <span className="toggle-label">{label}</span>
        {hint && <span className="toggle-hint">{hint}</span>}
      </span>
    </label>
  );
}
