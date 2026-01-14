#!/usr/bin/env bash
set -euo pipefail

# ===== Pré-checks =====
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo "Erreur: Bash 4+ est requis pour les tableaux associatifs." >&2
  exit 1
fi

# ===== Config =====
SUSPICIOUS_MARKERS=( "/JavaScript" "/OpenAction" "/AA" "/Launch" "/EmbeddedFile" "/RichMedia" )
WATCH_MARKERS=( "/AcroForm" "/SubmitForm" "/GoToE" "/JBIG2Decode" "/ObjStm" )
MAX_SIZE=$((100 * 1024 * 1024))  # 100 MiB max
VT_API_URL="https://www.virustotal.com/api/v3/files"   # GET /{sha256}

# ===== Helpers =====
log() { printf "[%s] %s\n" "$(date +'%F %T')" "$*"; }
die() { echo "Erreur: $*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }
can_sudo() { command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; }

ensure_home_bin_in_path() {
  if [[ -d "$HOME/bin" ]]; then
    export PATH="$HOME/bin:$PATH"
  fi
}

detect_pkg_mgr() {
  if need_cmd yay; then echo "yay"; return; fi
  if need_cmd pacman; then echo "pacman"; return; fi
  if need_cmd apt-get; then echo "apt"; return; fi
  if need_cmd dnf; then echo "dnf"; return; fi
  if need_cmd yum; then echo "yum"; return; fi
  if need_cmd brew; then echo "brew"; return; fi
  echo "none"
}

install_sys_pkgs() {
  local mgr="$1"; shift
  local pkgs=("$@")
  case "$mgr" in
    yay)    yay -S --needed --noconfirm "${pkgs[@]}" ;;
    pacman)
      can_sudo || die "sudo requis pour pacman. Relance en root ou active sudo."
      sudo pacman -Sy --noconfirm "${pkgs[@]}"
      ;;
    apt)
      can_sudo || die "sudo requis pour apt. Relance en root ou active sudo."
      sudo apt-get update -y && sudo apt-get install -y "${pkgs[@]}"
      ;;
    dnf)
      can_sudo || die "sudo requis pour dnf. Relance en root ou active sudo."
      sudo dnf check-update -y || true && sudo dnf install -y "${pkgs[@]}"
      ;;
    yum)
      can_sudo || die "sudo requis pour yum. Relance en root ou active sudo."
      sudo yum check-update -y || true && sudo yum install -y "${pkgs[@]}"
      ;;
    brew)   brew update || true && brew install "${pkgs[@]}" ;;
    *)      die "Aucun gestionnaire de paquets compatible détecté (installe manuellement : ${pkgs[*]})." ;;
  esac
}

ensure_tool() {
  # Télécharge un script CLI (sans pip) dans ~/bin si absent
  local name="$1" url="$2"
  if ! need_cmd "$name"; then
    log "Téléchargement $name"
    mkdir -p "$HOME/bin"
    curl -fL --retry 3 --retry-delay 1 "$url" -o "$HOME/bin/${name}.py"
    chmod +x "$HOME/bin/${name}.py"
    cat > "$HOME/bin/$name" <<EOF
#!/usr/bin/env bash
exec python3 "\$HOME/bin/${name}.py" "\$@"
EOF
    chmod +x "$HOME/bin/$name"
    ensure_home_bin_in_path
    hash -r
    need_cmd "$name" || die "$name introuvable après installation."
  fi
}

sha256() {
  if need_cmd sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  elif need_cmd shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "sha256sum/shasum introuvable"
  fi
}

num_or_zero() {
  # retourne un entier >=0, sinon 0
  local v="${1:-0}"
  v="${v//$'\n'/}"; v="${v//[^0-9]/}"
  [[ -z "$v" ]] && v=0
  echo "$v"
}

pdfparser_search() {
  # Compat: certaines versions n'ont pas -q
  local pattern="$1" file="$2"
  if pdf-parser -q -s "$pattern" "$file" 2>/dev/null; then
    return 0
  else
    pdf-parser -s "$pattern" "$file"
    return $?
  fi
}

# ===== Argument =====
FILE="${1:-}"
[[ -n "${FILE}" ]] || die "Usage: $0 /chemin/vers/fichier.pdf"
[[ -f "${FILE}" ]] || die "Fichier introuvable: $FILE"

ensure_home_bin_in_path

log "Analyse de: ${FILE}"

SIZE_BYTES=$(stat -c%s "$FILE" 2>/dev/null || stat -f%z "$FILE")
(( SIZE_BYTES > MAX_SIZE )) && die "Fichier trop gros (${SIZE_BYTES} octets > ${MAX_SIZE})"

# ===== Dépendances système =====
PKG_MGR=$(detect_pkg_mgr)
log "Gestionnaire de paquets: ${PKG_MGR}"

# Paquets de base (dépendants du gestionnaire)
case "$PKG_MGR" in
  yay|pacman) SYS_PKGS=(clamav exiftool python python-pip curl) ;;
  apt|dnf|yum) SYS_PKGS=(clamav exiftool python3 python3-pip curl) ;;
  brew) SYS_PKGS=(clamav exiftool python curl) ;;
  *) SYS_PKGS=() ;;
esac
MISSING=()
for c in clamscan exiftool python3 curl; do
  need_cmd "$c" || MISSING+=("$c")
done
if ((${#MISSING[@]})); then
  if ((${#SYS_PKGS[@]})); then
    log "Installation des dépendances système manquantes: ${SYS_PKGS[*]}"
    install_sys_pkgs "$PKG_MGR" "${SYS_PKGS[@]}"
  else
    die "Gestionnaire de paquets inconnu. Installe manuellement: ${MISSING[*]}"
  fi
fi

# ===== Outils PDF (téléchargements directs) =====
ensure_tool "pdfid"      "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdfid.py"
ensure_tool "pdf-parser" "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py"
ensure_tool "peepdf"     "https://raw.githubusercontent.com/jesparza/peepdf/master/peepdf/peepdf.py"

# ===== VirusTotal: invite pour clé (optionnelle) =====
if [[ -z "${VT_API_KEY:-}" ]]; then
  echo -n "Entrer la clé API VirusTotal (laisser vide pour passer) : "
  if [[ -t 0 ]]; then read -rs VT_API_KEY_INPUT || VT_API_KEY_INPUT=""; echo; else read VT_API_KEY_INPUT || VT_API_KEY_INPUT=""; fi
  [[ -n "$VT_API_KEY_INPUT" ]] && export VT_API_KEY="$VT_API_KEY_INPUT"
fi

# ===== Analyses =====
TMPDIR="$(mktemp -d)"; trap 'rm -rf "$TMPDIR"' EXIT
SHA256_VAL=$(sha256 "$FILE")
log "SHA256: $SHA256_VAL"

# 1) pdfid
log "pdfid: détection de marqueurs suspects…"
PDFID_OUT="$TMPDIR/pdfid.txt"
pdfid "$FILE" > "$PDFID_OUT" || true

get_marker_count() { awk -v m="$1" '$1==m {print $2}' "$PDFID_OUT" | tr -d '()' || echo "0"; }

declare -A MARKER_COUNTS=()
for m in "${SUSPICIOUS_MARKERS[@]}"; do
  MARKER_COUNTS["$m"]="$(num_or_zero "$(get_marker_count "$m" | awk '{sum+=$1} END {print sum+0}')")"
done
declare -A WATCH_COUNTS=()
for m in "${WATCH_MARKERS[@]}"; do
  WATCH_COUNTS["$m"]="$(num_or_zero "$(get_marker_count "$m" | awk '{sum+=$1} END {print sum+0}')")"
done

# 2) pdf-parser
log "pdf-parser: recherche ciblée…"
PARSER_JS="$TMPDIR/pdfparser_js.txt"
PARSER_OA="$TMPDIR/pdfparser_oa.txt"
pdfparser_search "/JavaScript" "$FILE" > "$PARSER_JS"  || true
pdfparser_search "/OpenAction" "$FILE" > "$PARSER_OA"  || true
HAS_JS=$([ -s "$PARSER_JS" ] && echo true || echo false)
HAS_OA=$([ -s "$PARSER_OA" ] && echo true || echo false)

# 3) peepdf
log "peepdf: analyse globale…"
PEEPDF_OUT="$TMPDIR/peepdf.txt"
peepdf -f "$FILE" > "$PEEPDF_OUT" 2>/dev/null || true
PEEPDF_JS="$(num_or_zero "$(grep -ic "JavaScript" "$PEEPDF_OUT" 2>/dev/null || echo 0)")"
PEEPDF_SUSP="$(num_or_zero "$(grep -iEc "suspicious|vulnerab" "$PEEPDF_OUT" 2>/dev/null || echo 0)")"

# 4) ClamAV
log "ClamAV: scan antivirus…"
CLAM_OUT="$TMPDIR/clamav.txt"
if need_cmd freshclam; then
  if can_sudo; then sudo freshclam >/dev/null 2>&1 || true; else freshclam >/dev/null 2>&1 || true; fi
fi
clamscan "$FILE" > "$CLAM_OUT" || true
CLAM_INF="$(num_or_zero "$(grep -c "FOUND" "$CLAM_OUT" 2>/dev/null || echo 0)")"

# 5) exiftool
log "exiftool: métadonnées…"
EXIF_OUT="$TMPDIR/exif.txt"
exiftool "$FILE" > "$EXIF_OUT" || true
FILETYPE=$(grep -E "^File Type *:" "$EXIF_OUT" | awk -F': ' '{print $2}' | xargs)
PAGECOUNT=$(grep -E "^Page Count *:" "$EXIF_OUT" | awk -F': ' '{print $2}' | xargs)

# 6) VirusTotal (HTTP, si clé fournie)
VT_POSITIVES=""; VT_TOTAL=""
if [[ -n "${VT_API_KEY:-}" ]]; then
  log "VirusTotal: lookup par hash via API…"
  VT_JSON_FILE="$TMPDIR/vt.json"
  VT_HTTP="$(curl -sS --retry 3 --retry-delay 1 -H "x-apikey: ${VT_API_KEY}" -o "$VT_JSON_FILE" -w "%{http_code}" "${VT_API_URL}/${SHA256_VAL}" || true)"
  if [[ "$VT_HTTP" == "200" ]]; then
    VT_JSON="$(cat "$VT_JSON_FILE")"
    VT_POSITIVES="$(
      VT_JSON="$VT_JSON" python3 - <<'PY'
import os, json
try:
    d = json.loads(os.environ.get("VT_JSON","") or "{}")
    stats = d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
    print(int(stats.get("malicious", 0)))
except Exception:
    print("")
PY
    )"
    VT_TOTAL="$(
      VT_JSON="$VT_JSON" python3 - <<'PY'
import os, json
try:
    d = json.loads(os.environ.get("VT_JSON","") or "{}")
    stats = d.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
    print(sum(int(v) for v in stats.values() if isinstance(v,int)))
except Exception:
    print("")
PY
    )"
  elif [[ "$VT_HTTP" == "404" ]]; then
    log "VirusTotal: hash inconnu (404)."
  elif [[ -n "$VT_HTTP" ]]; then
    log "VirusTotal: erreur HTTP ${VT_HTTP}."
  fi
fi

# ===== Scoring & axes de risque =====
risk_score=0
axes_triggered=()

add_axis() { axes_triggered+=("$1"); }

# Réputation / AV / VT
if (( CLAM_INF > 0 )); then risk_score=$((risk_score+100)); add_axis "Réputation/AV: ClamAV FOUND"; fi
if [[ -n "${VT_POSITIVES:-}" ]]; then
  vtpos="$(num_or_zero "$VT_POSITIVES")"
  if (( vtpos >= 3 )); then risk_score=$((risk_score+80)); add_axis "Réputation/VT: ${vtpos} positifs"; 
  elif (( vtpos >= 1 )); then risk_score=$((risk_score+60)); add_axis "Réputation/VT: ${vtpos} positifs"; fi
fi

# Auto-exécution
if [[ "$HAS_OA" == true ]] || (( ${MARKER_COUNTS["/OpenAction"]} > 0 )) || (( ${MARKER_COUNTS["/AA"]} > 0 )); then
  risk_score=$((risk_score+40)); add_axis "Auto-exécution: OpenAction/AA";
fi

# Script/JS
if [[ "$HAS_JS" == true ]] || (( ${MARKER_COUNTS["/JavaScript"]} > 0 )); then
  risk_score=$((risk_score+40)); add_axis "Script/JavaScript";
fi

# Lancement externe
if (( ${MARKER_COUNTS["/Launch"]} > 0 )); then
  risk_score=$((risk_score+50)); add_axis "Lancement externe (/Launch)";
fi

# Contenu embarqué
if (( ${MARKER_COUNTS["/EmbeddedFile"]} > 0 )) || (( ${MARKER_COUNTS["/RichMedia"]} > 0 )); then
  risk_score=$((risk_score+30)); add_axis "Contenu embarqué (EmbeddedFile/RichMedia)";
fi

# Objets/Formulaires & navigation
if (( ${WATCH_COUNTS["/AcroForm"]} > 0 )) || (( ${WATCH_COUNTS["/SubmitForm"]} > 0 )) || (( ${WATCH_COUNTS["/ObjStm"]} > 0 )) || (( ${WATCH_COUNTS["/GoToE"]} > 0 )); then
  risk_score=$((risk_score+20)); add_axis "Objets/Formulaires/Navigation";
fi

# Indices d’exploit
if (( ${WATCH_COUNTS["/JBIG2Decode"]} > 0 )); then
  risk_score=$((risk_score+25)); add_axis "Indice d’exploit (JBIG2Decode)";
fi

# Type inattendu
if [[ -n "$FILETYPE" && "${FILETYPE^^}" != "PDF" ]]; then
  risk_score=$((risk_score+50)); add_axis "Incohérence de type";
fi

# Confiance du verdict (faible/moyenne/élevée)
confidence="faible"
if (( CLAM_INF > 0 )) || { [[ -n "$VT_POSITIVES" ]] && (( $(num_or_zero "$VT_POSITIVES") > 0 )); }; then
  confidence="élevée"
elif [[ "$HAS_JS" == true || "$HAS_OA" == true ]] || (( ${MARKER_COUNTS["/Launch"]} > 0 )); then
  confidence="moyenne"
fi

# Niveau
risk_level="LOW"
if   (( risk_score >= 100 )); then risk_level="CRITICAL"
elif (( risk_score >= 70 ));  then risk_level="HIGH"
elif (( risk_score >= 40 ));  then risk_level="MEDIUM"
else risk_level="LOW"; fi

# ===== Rapport =====
echo
echo "==================== RÉSULTATS ===================="
echo "Fichier : ${FILE:-(inconnu)}"
echo "SHA256  : ${SHA256_VAL}"
echo "Type    : ${FILETYPE:-inconnu}"
echo "Taille  : ${SIZE_BYTES} octets"
[[ -n "${PAGECOUNT:-}" ]] && echo "Pages   : ${PAGECOUNT}"

echo
echo "---- pdfid (marqueurs principaux) ----"
for m in "${SUSPICIOUS_MARKERS[@]}"; do printf "%-16s : %s\n" "$m" "${MARKER_COUNTS[$m]}"; done
echo
echo "---- pdfid (autres marqueurs) ----"
for m in "${WATCH_MARKERS[@]}"; do printf "%-16s : %s\n" "$m" "${WATCH_COUNTS[$m]}"; done
echo
echo "---- pdf-parser ----"
echo "JavaScript    : ${HAS_JS}"
echo "OpenAction    : ${HAS_OA}"
echo
echo "---- peepdf ----"
echo "Mentions JavaScript : ${PEEPDF_JS}"
echo "Mentions suspicious : ${PEEPDF_SUSP}"
echo
echo "---- ClamAV ----"
grep -E "Infected files:" "$CLAM_OUT" 2>/dev/null || true
grep -E "FOUND" "$CLAM_OUT" 2>/dev/null || true
if [[ -n "${VT_POSITIVES}${VT_TOTAL}" ]]; then
  echo
  echo "---- VirusTotal (hash lookup) ----"
  echo "Détections : ${VT_POSITIVES:-0}/${VT_TOTAL:-0}"
  echo "Note: si le hash est inconnu de VT, il se peut qu'aucune donnée ne soit renvoyée."
fi

echo
echo "==== VERDICT FINAL ===="
printf "Niveau  : %s\n" "$risk_level"
printf "Score   : %s/150 (approx.)\n" "$risk_score"
printf "Confiance : %s\n" "$confidence"
if ((${#axes_triggered[@]})); then
  echo "Biais malveillants détectés :"
  for a in "${axes_triggered[@]}"; do echo "  - $a"; done
else
  echo "Aucun biais malveillant évident détecté (attention: l'absence de signal n'est pas une garantie)."
fi

# ===== Résumé JSON =====
echo
echo "---- Résumé JSON ----"
python3 - <<PY
import json
print(json.dumps({
  "file": "${FILE}",
  "sha256": "${SHA256_VAL}",
  "size_bytes": ${SIZE_BYTES},
  "filetype": "${FILETYPE}",
  "page_count": "${PAGECOUNT}",
  "risk_score": ${risk_score},
  "risk_level": "${risk_level}",
  "confidence": "${confidence}",
  "axes_triggered": ${axes_triggered[@]+"["}$(printf '"%s",' "${axes_triggered[@]}" 2>/dev/null | sed 's/,$//')${axes_triggered[@]+"]"},
  "virus_total": {"positives": "${VT_POSITIVES}", "total": "${VT_TOTAL}"}
}, ensure_ascii=False, indent=2))
PY
