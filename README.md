# traitement-ANSSI

Analyse automatisée des bulletins de sécurité ANSSI avec enrichissement des CVE, filtrage avancé, visualisation et envoi de notifications par email.

## Objectif

Ce projet vise à automatiser le traitement des avis et alertes de sécurité publiés par l'ANSSI. L'application collecte les flux RSS, extrait les identifiants CVE, les enrichit via des API externes (MITRE, EPSS), filtre les vulnérabilités critiques et envoie des alertes personnalisées aux abonnés.

## Fonctionnalités

### Extraction RSS
- Téléchargement et parsing des flux RSS d'avis et alertes de l'ANSSI.
- Extraction des bulletins JSON liés à chaque publication.

### Traitement des CVE
- Extraction des identifiants CVE dans chaque bulletin.
- Enrichissement via API MITRE (description, score CVSS, CWE, produits affectés).
- Récupération du score EPSS via l'API de first.org.

### Filtrage intelligent
- Consolidation dans un DataFrame Pandas.
- Nettoyage, normalisation, suppression des doublons.
- Filtrage par score CVSS, disponibilité des données, pertinence.
- Export CSV (`cve_data.csv`).

### Envoi d’alertes par email
- Système de gestion des abonnés avec préférences produits.
- Génération de résumés de vulnérabilités critiques personnalisés.
- Envoi automatique des rapports par email.

### Interface graphique
- Développée avec Tkinter.
- Interface avec boutons d'action, barre de progression, terminal d'exécution.
- Fenêtres supplémentaires : gestion des abonnés, crédits, informations.

## Structure recommandée

## Dépendances

- Python >= 3.8
- feedparser
- pandas
- requests
- tqdm
- smtplib (librairie standard)
- tkinter (installé avec Python)
- email (librairie standard)

Installation :

```bash
pip install -r requirements.txt

