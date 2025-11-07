# audit-pdf.sh

Script Bash pour auditer la sécurité d'un fichier PDF en ligne de commande.  
Il combine des analyses statiques (structures PDF), antivirus (ClamAV) et réputation (VirusTotal) pour mettre en évidence des comportements potentiellement malveillants, et produit un verdict détaillé, pondéré et exploitable en CI/CD.

---

## Sommaire

- [Objectifs](#objectifs)
- [Fonctionnalités](#fonctionnalités)
- [Compatibilité et dépendances](#compatibilité-et-dépendances)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Sortie détaillée](#sortie-détaillée)
- [Résumé JSON](#résumé-json)
- [Variables d’environnement](#variables-denvironnement)
- [Sécurité et modèle de confiance](#sécurité-et-modèle-de-confiance)
- [Dépannage](#dépannage)
- [Exemples](#exemples)
- [CI GitHub Actions](#ci-github-actions)
- [Licence](#licence)
- [Crédits](#crédits)

---

## Objectifs

- Identifier des structures PDF dangereuses : `/JavaScript`, `/OpenAction`, `/Launch`, fichiers embarqués, etc.
- Détecter d’éventuelles signatures d’infection via ClamAV.
- Inspecter les métadonnées avec ExifTool.
- Évaluer la réputation via VirusTotal (lookup par hash, sans upload).
- Fournir un verdict explicite : score, niveau de risque, biais malveillants (axes), confiance.
- Produire un résumé JSON adapté à l’intégration CI/CD.

---

## Fonctionnalités

- Analyse statique PDF : `pdfid`, `pdf-parser`, `peepdf`
- Antivirus : `clamscan` (ClamAV)
- Métadonnées : `exiftool`
- Réputation : VirusTotal (API v3 via `curl`; clé optionnelle)
- Verdict riche :
  - Score de risque (0–150+)
  - Niveau (LOW / MEDIUM / HIGH / CRITICAL)
  - Confiance (faible / moyenne / élevée)
  - Biais malveillants détectés (axes) : auto-exécution, scripts, lancement externe, contenu embarqué, formulaires/objets, indice d’exploit, réputation, incohérence de type
- Sortie lisible + JSON final pour automatisation

---

## Compatibilité et dépendances

Le script installe automatiquement les dépendances manquantes (si possible) :

| Système      | Gestionnaire                | Paquets système installés                                  |
|--------------|-----------------------------|-------------------------------------------------------------|
| Arch Linux   | `yay` (prioritaire) ou `pacman` | `clamav`, `exiftool`, `python`, `python-pip`, `curl`     |
| Debian/Ubuntu| `apt-get`                   | `clamav`, `exiftool`, `python3`, `python3-pip`, `curl`     |
| Fedora       | `dnf`                       | `clamav`, `exiftool`, `python3`, `python3-pip`, `curl`     |
| macOS        | `brew`                      | `clamav`, `exiftool`, `python`, `curl`                     |

Outils PDF téléchargés si absents (depuis GitHub, version CLI autonome) :
- `pdfid`, `pdf-parser` (Didier Stevens)
- `peepdf` (José Miguel Esparza)

Le script n’utilise pas `vt-cli`; l’API VirusTotal est appelée via `curl`.

---

## Installation

```bash
git clone https://github.com/<ton-utilisateur>/audit-pdf.git
cd audit-pdf
chmod +x audit-pdf.sh
```

Optionnel : installation système

```bash
sudo mv audit-pdf.sh /usr/local/bin/audit-pdf
```

---

## Utilisation

```bash
./audit-pdf.sh /chemin/vers/fichier.pdf
```

Pendant l’exécution :
- Si `VT_API_KEY` est absent, le script propose de coller la clé VirusTotal (masquée). Étape facultative.
- Les dépendances manquantes sont installées via le gestionnaire détecté.

---

## Sortie détaillée

Exemple abrégé :

```
==================== RÉSULTATS ====================
Fichier : sample.pdf
SHA256  : 3f0b6e...
Type    : PDF
Taille  : 125084 octets
Pages   : 5

---- pdfid (marqueurs principaux) ----
/JavaScript     : 1
/OpenAction     : 1
...

---- ClamAV ----
Infected files: 0

---- VirusTotal (hash lookup) ----
Détections : 2/71

==== VERDICT FINAL ====
Niveau  : HIGH
Score   : 85/150
Confiance : moyenne
Biais malveillants détectés :
  - Script/JavaScript
  - Auto-exécution: OpenAction/AA
  - Réputation/VT: 2 positifs
```

---

## Résumé JSON

Le script produit un JSON en fin d’exécution :

```json
{
  "file": "sample.pdf",
  "sha256": "3f0b6e...",
  "size_bytes": 125084,
  "filetype": "PDF",
  "page_count": "5",
  "risk_score": 85,
  "risk_level": "HIGH",
  "confidence": "moyenne",
  "axes_triggered": [
    "Script/JavaScript",
    "Auto-exécution: OpenAction/AA",
    "Réputation/VT: 2 positifs"
  ],
  "virus_total": {
    "positives": "2",
    "total": "71"
  }
}
```

---

## Variables d’environnement

| Variable    | Description                                             |
|-------------|---------------------------------------------------------|
| `VT_API_KEY`| Clé API VirusTotal. Optionnelle. Ignorée si absente.   |

---

## Sécurité et modèle de confiance

- Le script n’ouvre jamais le PDF dans un lecteur. Analyses statiques uniquement + AV + réputation.
- L’absence de détection n’est pas une preuve d’innocuité. Pour des environnements sensibles, compléter par sandbox/VM et analyses dynamiques.
- VirusTotal peut ne rien renvoyer si le hash est inconnu, et le quota dépend du plan API.

---

## Dépannage

- `pdf-parser: error: no such option: -q`  
  Géré automatiquement : le script tente avec `-q`, puis retombe sans `-q`.
- `freshclam` permission denied  
  Le script tente `sudo freshclam` si possible, sinon ignore la mise à jour. Le scan continue.
- Réponse VirusTotal vide  
  Hash inconnu ou limite de quota atteinte. Réessayer plus tard, ou fournir une clé valide.

---

## Exemples

Audit simple sans VirusTotal :
```bash
./audit-pdf.sh ~/docs/rapport.pdf
```

Avec VirusTotal :
```bash
export VT_API_KEY="xxxxx"
./audit-pdf.sh ~/Téléchargements/facture.pdf
```

Extraction du JSON seulement (pour CI) :
```bash
./audit-pdf.sh fichier.pdf | awk '/---- Résumé JSON ----/{flag=1;next}/^$/{flag=0}flag'
```

---

## CI GitHub Actions

Badge à ajouter en haut du README lorsque le workflow est en place :

```
![CI](https://github.com/<ton-utilisateur>/audit-pdf/actions/workflows/ci.yml/badge.svg)
```

Workflow minimal `.github/workflows/ci.yml` :

```yaml
name: CI

on:
  push:
    branches: [ "**" ]
  pull_request:
    branches: [ "**" ]

jobs:
  lint-and-test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install shellcheck
        run: sudo apt-get update && sudo apt-get install -y shellcheck

      - name: Lint script
        run: shellcheck -x audit-pdf.sh

      - name: Make executable
        run: chmod +x audit-pdf.sh

      - name: Smoke test (no VT)
        run: |
          echo "%PDF-1.1
          1 0 obj<<>>endobj
          trailer<<>>startxref
          0
          %%EOF" > sample.pdf
          ./audit-pdf.sh sample.pdf || true

      - name: Extract JSON block
        run: |
          ./audit-pdf.sh sample.pdf | awk '/---- Résumé JSON ----/{flag=1;next}/^$/{flag=0}flag' | tee result.json
          test -s result.json
```

---

## Licence

Ce projet est distribué sous licence MIT.

```
MIT License

Copyright (c) 2025 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights   
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell       
copies of the Software, and to permit persons to whom the Software is          
furnished to do so, subject to the following conditions:                       

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.                                 

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  
SOFTWARE.
```

---

## Crédits

- Outils d’analyse PDF : `pdfid`, `pdf-parser` (Didier Stevens), `peepdf` (José Miguel Esparza)
- Antivirus : `ClamAV`
- Métadonnées : `ExifTool`
- Réputation : `VirusTotal`
