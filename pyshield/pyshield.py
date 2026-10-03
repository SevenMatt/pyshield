import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

DANGEROUS_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".hta", ".jar",
    ".lnk", ".cpl", ".psm1", ".dll"
}

HEURISTIC_PATTERNS = [
    b"powershell -enc", b"powershell -w hidden", b"-nop -w hidden",
    b"invoke-expression", b"iex (new-object", b"downloadstring",
    b"cmd /c start", b"regsvr32 /s", b"certutil -urlcache",
    b"vssadmin delete shadows", b"bcdedit /set", b"wscript.shell",
    b"createobject(\"msxml2", b"shell.application",
]

STARTUP_DIRS = [
    os.path.expandvars(r"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
    os.path.expandvars(r"%TEMP%"),
]

VT_URL = "https://www.virustotal.com/api/v3/files/"


def load_signatures(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return {k.lower(): v for k, v in json.loads(p.read_text()).items()}
    except (json.JSONDecodeError, ValueError):
        print(f"[!] Banco de assinaturas inválido: {path}")
        return {}


def file_hash(path: str, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def heuristic_scan(path: str) -> list:
    reasons = []
    name = os.path.basename(path)
    parts = name.lower().split(".")
    if len(parts) > 2 and ("." + parts[-1]) in DANGEROUS_EXTS:
        reasons.append("extensão dupla suspeita")
    try:
        size = os.path.getsize(path)
        if size > 5 * 1024 * 1024:
            return reasons
        with open(path, "rb") as f:
            data = f.read()
        low = data.lower()
        for pat in HEURISTIC_PATTERNS:
            if pat in low:
                reasons.append(f"padrão suspeito: {pat.decode(errors='ignore')!r}")
                break
    except (PermissionError, OSError):
        pass
    return reasons


def vt_lookup(sha256: str, api_key: str) -> dict:
    if not HAS_REQUESTS:
        return {"error": "módulo requests não instalado"}
    try:
        r = requests.get(
            VT_URL + sha256,
            headers={"x-apikey": api_key},
            timeout=30,
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
        if r.status_code == 404:
            return {"malicious": 0, "suspicious": 0, "note": "desconhecido no VT"}
        if r.status_code == 429:
            time.sleep(60)
            return vt_lookup(sha256, api_key)
        return {"error": f"HTTP {r.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def quarantine(path: str, quarantine_dir: str) -> str:
    qdir = Path(quarantine_dir)
    qdir.mkdir(parents=True, exist_ok=True)
    dest = qdir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.path.basename(path)}.quar"
    shutil.move(path, dest)
    return str(dest)


def scan(root: str, sigs: dict, vt_key: str = "", quarantine_dir: str = "",
          delete: bool = False, use_heuristics: bool = True) -> list:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(path) > 200 * 1024 * 1024:
                    continue 
                sha = file_hash(path)
            except (PermissionError, OSError):
                continue

            name = sigs.get(sha)
            vt = None
            if name:
                sev = "MALICIOSO (assinatura)"
            elif vt_key:
                vt = vt_lookup(sha, vt_key)
                if vt.get("malicious", 0) >= 3:
                    name = f"Detectado por {vt['malicious']} engines no VirusTotal"
                    sev = "MALICIOSO (VirusTotal)"
            if name is None:
                if use_heuristics:
                    reasons = heuristic_scan(path)
                    if reasons:
                        findings.append({
                            "path": path, "sha256": sha,
                            "sev": "SUSPEITO (heurística)", "detail": "; ".join(reasons),
                            "vt": vt,
                        })
                continue

            findings.append({
                "path": path, "sha256": sha, "sev": sev, "detail": name, "vt": vt,
            })

    for f in findings:
        if not f["sev"].startswith("MALICIOSO"):
            continue
        if delete:
            try:
                os.remove(f["path"])
                f["action"] = "REMOVIDO"
            except OSError as e:
                f["action"] = f"falha ao remover: {e}"
        elif quarantine_dir:
            try:
                f["action"] = f"quarentena -> {quarantine(f['path'], quarantine_dir)}"
            except OSError as e:
                f["action"] = f"falha na quarentena: {e}"
        else:
            f["action"] = "nenhuma (apenas relatório)"
    return findings


def main():
    ap = argparse.ArgumentParser(
        prog="pyshield",
        description="PyShield — scanner antimalware simples (uso defensivo/educacional).",
    )
    ap.add_argument("path", nargs="?", default=".", help="diretório a escanear (padrão: atual)")
    ap.add_argument("--sigs", default="signatures.json", help="banco de assinaturas SHA256")
    ap.add_argument("--vt-key", default=os.environ.get("VT_API_KEY", ""),
                    help="chave da API VirusTotal (ou variável VT_API_KEY)")
    ap.add_argument("--quarantine", default="", help="diretório de quarentena")
    ap.add_argument("--delete", action="store_true", help="apagar maliciosos confirmados (irreversível!)")
    ap.add_argument("--no-heuristics", action="store_true", help="desativar varredura heurística")
    args = ap.parse_args()

    print(f"[*] PyShield — escaneando {os.path.abspath(args.path)} ...")
    sigs = load_signatures(args.sigs)
    print(f"[*] {len(sigs)} assinaturas carregadas")

    t0 = time.time()
    findings = scan(args.path, sigs, args.vt_key, args.quarantine,
                    args.delete, not args.no_heuristics)

    print(f"\n[*] Varredura concluída em {time.time() - t0:.1f}s — {len(findings)} achado(s):\n")
    for f in findings:
        print(f"  [{f['sev']}] {f['path']}")
        print(f"      SHA256: {f['sha256']}")
        print(f"      Detalhe: {f['detail']}")
        if f.get("vt"):
            print(f"      VirusTotal: {f['vt']}")
        if f.get("action"):
            print(f"      Ação: {f['action']}")
        print()

    if not findings:
        print("Nenhuma ameaça encontrada. Sistema limpo.")


if __name__ == "__main__":
    main()