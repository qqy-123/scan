import io
import re
from urllib.parse import urlsplit

URL_RE = re.compile(
    r"(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d{1,5})?(?:/[^\s'\"<>\\]*)?"
)


def normalize(url: str) -> str | None:
    """Normalize a URL. Keeps missing scheme so probe can try https then http."""
    url = url.strip().strip("'\"").rstrip("/.,;")
    if not url or " " in url:
        return None
    if not urlsplit(url if "//" in url else "//" + url).hostname:
        return None
    return url


def dedupe(urls: list[str]) -> list[str]:
    seen, out = set(), []
    for u in urls:
        n = normalize(u)
        if n and n.lower() not in seen:
            seen.add(n.lower())
            out.append(n)
    return out


def from_text(text: str) -> list[str]:
    return dedupe(URL_RE.findall(text))


def from_xlsx(data: bytes) -> list[str]:
    import openpyxl

    wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    found = []
    for ws in wb.worksheets:
        for row in ws.iter_rows(values_only=True):
            for cell in row:
                if isinstance(cell, str):
                    found.extend(URL_RE.findall(cell))
                elif isinstance(cell, (int, float)) and cell == int(cell):
                    continue
    wb.close()
    return dedupe(found)


def from_xls(data: bytes) -> list[str]:
    """Legacy .xls (OLE) workbook — openpyxl can't read it, xlrd can."""
    import xlrd

    wb = xlrd.open_workbook(file_contents=data)
    found = []
    for ws in wb.sheets():
        for rx in range(ws.nrows):
            for cell in ws.row_values(rx):
                if isinstance(cell, str):
                    found.extend(URL_RE.findall(cell))
    return dedupe(found)


def from_file(name: str, data: bytes) -> list[str]:
    """Dispatch by extension; anything else is treated as text."""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext in ("xlsx", "xlsm"):
        return from_xlsx(data)
    if ext == "xls":
        return from_xls(data)
    return from_text(data.decode("utf-8", "ignore"))
