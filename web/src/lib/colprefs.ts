/* Versioned column-visibility prefs in localStorage — same format the
   Vue frontend uses so existing settings carry over. */

interface Prefs {
  v: number;
  cols: string[];
}

export function loadColPrefs(
  key: string,
  all: string[],
  version: number,
): string[] {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return all;
    let cols: string[] | null = null;
    let v = 0;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      cols = parsed; // legacy v0: bare array
    } else if (parsed && Array.isArray((parsed as Prefs).cols)) {
      cols = (parsed as Prefs).cols;
      v = (parsed as Prefs).v || 0;
    }
    if (!cols) return all;
    const known = new Set(all);
    const clean = cols.filter((c): c is string => typeof c === "string" && known.has(c));
    if (v < version) {
      // merge in columns added since the saved version
      for (const c of all) if (!clean.includes(c)) clean.push(c);
    }
    return clean;
  } catch {
    return all;
  }
}

export function saveColPrefs(
  key: string,
  visible: string[],
  all: string[],
  version: number,
) {
  const known = new Set(all);
  const cols = visible.filter((c) => known.has(c));
  localStorage.setItem(key, JSON.stringify({ v: version, cols } as Prefs));
}
