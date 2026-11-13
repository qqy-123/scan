// 表格列显示偏好的 localStorage 持久化。
//
// 存储形态 {v, cols}：v 是列集合版本号——列增删时 +1。
// - 旧版偏好（v 更小）里缺失、且在新版才引入的列（since[key]>v）默认并入，
//   让新列对老用户直接可见，而不是静默消失
// - 存储里已不存在的 key（列被删/脏数据如 null）自动剔除
// - 数据损坏或缺失时回退为全部列
//
// since: {key: ver} 标记每列引入时的版本；新列记得登记并 bump ver。
export function loadColPrefs(lsKey, allKeys, ver, since = {}) {
  let s = null
  try {
    s = JSON.parse(localStorage.getItem(lsKey) || 'null')
  } catch { /* corrupted -> defaults */ }
  if (Array.isArray(s)) s = { v: 1, cols: s } // v1 时期存的裸数组
  if (s && Array.isArray(s.cols)) {
    const sv = s.v || 1
    const kept = s.cols.filter((k) => allKeys.includes(k))
    const merged = new Set(kept)
    if (sv < ver) {
      for (const k of allKeys) if ((since[k] || 1) > sv) merged.add(k)
    }
    return [...merged]
  }
  return allKeys
}

export function saveColPrefs(lsKey, ver, cols) {
  localStorage.setItem(lsKey, JSON.stringify({ v: ver, cols }))
}
