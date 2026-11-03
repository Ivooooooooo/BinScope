export function fmtHex(value: number | null | undefined, pad = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return `0x${value.toString(16).toUpperCase().padStart(pad, "0")}`;
}

export function fmtNum(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return value.toLocaleString("en-US");
}

export function fmtBytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = value;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u += 1;
  }
  return u === 0 ? `${v} B` : `${v.toFixed(2)} ${units[u]}`;
}

export function fmtDate(unix: number | null | undefined): string {
  if (!unix) return "—";
  const d = new Date(unix * 1000);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toISOString().replace(".000Z", "Z");
}

export function fmtTimestamp(unix: number | null | undefined): string {
  if (!unix) return "—";
  const d = new Date(unix * 1000);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

export function shorten(value: string, max = 160): string {
  return value.length <= max ? value : `${value.slice(0, max)}…`;
}

export function severityClass(severity: string): string {
  return `badge badge-${severity}`;
}

export function statusLabel(status: string): string {
  switch (status) {
    case "complete":
      return "Complete";
    case "partial":
      return "Partial";
    case "failed":
      return "Failed";
    case "cancelled":
      return "Cancelled";
    default:
      return status;
  }
}
