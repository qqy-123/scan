// Shared display formatters.

// DB timestamps arrive in two shapes depending on engine:
//   sqlite  "2026-11-06 08:19:59"
//   pg      "2026-11-10T08:40:25.446398"
// Normalize both to "YYYY-MM-DD HH:mm".
export function fmtTime(s, fallback = '-') {
  if (!s) return fallback
  const m = String(s).match(
    /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?/)
  if (!m) return String(s).slice(0, 16)
  return `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}`
}
