
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 13 20:26:23 2025

@author: user hidden
"""
"""
                                                                        README 
Conseils d'utilisation:

1. Assurez-vous d'avoir téléchargé toutes les bibliothèques nécessaires.
2. Changez le chemin du fichier CSV pour l'extraction des données si besoin.
3. Ne vous connectez pas à un Wi-Fi organisationnel, cela bloque le protocole d'envoi des mails.

Manuel d'utilisation:
- Vous pouvez exécuter directement le code, une interface va s'afficher où vous pouvez lancer dans l'ordre les étapes du processus.
- Vérifiez bien que le dernier processus soit terminé via le terminal de votre éditeur de code avant de lancer le projet.
- Il y a un suivi disponible dans ce terminal (par exemple, Spyder) avec des barres de chargement `tqdm` permettant de suivre l'avancée des processus.
- Ne faites surtout aucune action lorsque qu'une action est en cours sous risque de faire planter le code (restez bien sur la page de l'interface !!).
- Pour l'envoi d'emails pour les centres d'intérêt, je vous conseille de saisir l'éditeur "Cisco" qui est la valeur par défaut.
- N'hésitez pas à me contacter en cas de problème et bonne découverte !!



Le code brut commence à L219
  


Résumé des fonctions : 
  
  Interface de Gestion des CVE

 Description
Ce projet est une interface graphique développée en Python utilisant Tkinter pour gérer les vulnérabilités CVE (Common Vulnerabilities and Exposures). L'application permet d'extraire des flux RSS, de traiter et d'enrichir les données CVE, de filtrer les CVE critiques et d'envoyer des notifications par email aux abonnés.

 Fonctionnalités

a. Extraction des données ANSSI
L'application récupère les flux RSS des avis et alertes de sécurité publiés par l'ANSSI (Agence nationale de la sécurité des systèmes d'information). Les flux RSS sont analysés pour extraire les informations pertinentes sur les vulnérabilités.

- Fonction `rss(url, max_entries=100)` : 
  - Cette fonction prend une URL de flux RSS et un nombre maximum d'entrées à extraire.
  - Elle utilise la bibliothèque `feedparser` pour analyser le flux RSS.
  - Elle retourne une liste de dictionnaires contenant les titres, descriptions, liens et dates de publication des entrées.

- Fonction `extraire_rss()`* : 
  - Cette fonction utilise la fonction `rss` pour extraire les flux RSS des avis et alertes de l'ANSSI.
  - Elle met à jour l'interface utilisateur avec le nombre d'entrées extraites.
  - Elle met à jour la barre de progression et affiche les messages dans la zone de texte de l'interface.
b. Enrichissement des données via API
Les données extraites sont enrichies en récupérant des informations supplémentaires via des API externes. Cela inclut des détails sur les CVE, les scores CVSS, les descriptions, les produits affectés, et les scores EPSS.

- Fonction `CVEDETAILS(cve_id)`: 
  - Cette fonction prend un identifiant CVE et récupère les détails associés via une API.
  - Elle retourne un dictionnaire contenant la description, le score CVSS, les informations CWE, les produits affectés et la date de publication.
  - En cas d'erreur, elle affiche un message d'erreur dans la zone de texte de l'interface.

- Fonction `EPSS_Score(cve_id)` : 
  - Cette fonction prend un identifiant CVE et récupère le score EPSS associé via une API.
  - Elle retourne le score EPSS ou "Non disponible" en cas d'erreur.
  - En cas d'erreur, elle affiche un message d'erreur dans la zone de texte de l'interface.

 c. Consolidation des données (DataFrame Pandas)
Les données enrichies sont consolidées dans un DataFrame Pandas. Ce DataFrame permet de structurer et de manipuler les données de manière efficace. Les données sont ensuite filtrées pour ne conserver que les CVE critiques.

- Fonction `filtrer_cves()`: 
  - Cette fonction crée un DataFrame Pandas à partir des données CVE enrichies.
  - Elle détermine la sévérité des CVE en fonction des scores CVSS.
  - Elle parse les informations des produits affectés.
  - Elle filtre les CVE critiques et les enregistre dans un fichier CSV.
  - Elle met à jour la barre de progression et affiche les messages dans la zone de texte de l'interface.

d. Génération d’alertes et notifications
L'application génère des alertes et des notifications basées sur les CVE critiques. Les notifications sont envoyées par email aux abonnés, avec des détails personnalisés en fonction de leurs centres d'intérêt.

- Fonction `Envoi_emails()` : 
  - Cette fonction envoie des notifications par email aux abonnés avec les détails des CVE critiques.
  - Les emails sont personnalisés en fonction des centres d'intérêt des abonnés.
  - Elle utilise la bibliothèque `smtplib` pour envoyer les emails via un serveur SMTP.
  - Elle met à jour la barre de progression et affiche les messages dans la zone de texte de l'interface.

e. Interface
L'interface graphique de l'application est développée avec Tkinter. Elle permet aux utilisateurs d'interagir facilement avec l'application, d'extraire et de traiter les données, de visualiser les résultats, et de gérer les abonnés. L'interface inclut des boutons pour chaque fonctionnalité, une barre de progression, et des zones de texte pour afficher les messages et les résultats.

- Fenêtre principale (`root`) : 
  - La fenêtre principale de l'application, configurée avec des labels, des boutons, une barre de progression et des zones de texte.
  - Elle affiche la date et l'heure actuelles, et permet de lancer les différentes opérations via des boutons.

- Gestion des abonnés: 
  - Permet d'ajouter ou de retirer des abonnés à la liste de diffusion via une interface dédiée.
  - Les abonnés peuvent être ajoutés avec leur adresse email, leur nom et leurs centres d'intérêt.
  - Les abonnés peuvent être retirés en entrant leur adresse email.

- Mise à jour de l'interface : 
  - Utilise des fonctions pour mettre à jour l'affichage de la date et de l'heure.
  - Affiche les messages et les résultats des différentes opérations dans une zone de texte.
  - Met à jour la barre de progression pour indiquer l'avancement des opérations.

 Description des Fonctions

`rss(url, max_entries=100)`
- Description : Analyse les flux RSS et retourne une liste de dictionnaires contenant les titres, descriptions, liens et dates de publication des entrées.
- Paramètres :
  - `url` : URL du flux RSS.
  - `max_entries` : Nombre maximum d'entrées à extraire.
- Retour: Liste de dictionnaires contenant les informations des entrées du flux RSS.

`CVES_Bulletins(json_url)`
- Description : Extrait les identifiants CVE des bulletins JSON.
- Paramètres :
  - `json_url` : URL du bulletin JSON.
- Retour: Liste des noms des CVE et liste des identifiants CVE extraits du bulletin JSON.

`ENTREES(entries, type_bulletin, max_cve_per_entry=5)`
- Description : Traite les entrées des flux RSS pour extraire les CVE.
- Paramètres :
  - `entries` : Liste des entrées du flux RSS.
  - `type_bulletin` : Type de bulletin (Avis ou Alerte).
  - `max_cve_per_entry` : Nombre maximum de CVE à extraire par entrée.
- Retour: Liste de dictionnaires contenant les informations des CVE extraites.

 `CVEDETAILS(cve_id)`
- Description: Récupère les détails d'un CVE via une API.
- Paramètres :
  - `cve_id` : Identifiant du CVE.
- Retour : Dictionnaire contenant les détails du CVE (description, score CVSS, informations CWE, produits affectés, date de publication).

`EPSS_Score(cve_id)`
- Description : Récupère le score EPSS d'un CVE via une API.
- Paramètres:
  - `cve_id` : Identifiant du CVE.
- Retour : Score EPSS du CVE ou "Non disponible" en cas d'erreur.

 `NORMALISE(s)`
- Description : Normalise une chaîne de caractères en remplaçant les apostrophes par des espaces et en retirant les accents.
- Paramètres:
  - `s` : Chaîne de caractères à normaliser.
- Retour : Chaîne de caractères normalisée.

 `DOUBLONS(s)`
- Description : Supprime les doublons dans une chaîne de caractères séparée par des points-virgules.
- Paramètres :
  - `s` : Chaîne de caractères à traiter.
- Retour : Chaîne de caractères sans doublons.

 `MAJ(s)`
- Description : Supprime les mentions "[MAJ]" dans une chaîne de caractères.
- Paramètres :
  - `s` : Chaîne de caractères à traiter.
- Retour : Chaîne de caractères sans les mentions "[MAJ]".

 `eemail(to_email, cc_email, subject, body)`
- Description : Envoie un email avec les détails des CVE.
- Paramètres :
  - `to_email` : Adresse email du destinataire.
  - `cc_email` : Adresse email en copie.
  - `subject` : Sujet de l'email.
  - `body` : Corps de l'email en HTML.
- **Retour** : Aucun.

`extraire_rss()`
- Description: Extrait les flux RSS des avis et alertes de l'ANSSI et met à jour l'interface utilisateur.
- Paramètres : Aucun.
- Retour : Aucun.

`extraire_cves()`
- Description : Extrait les CVE des avis et alertes et met à jour l'interface utilisateur.
- Paramètres : Aucun.
- Retour : Aucun.

`enrichir_cves()`
- Description: Enrichit les CVE avec des informations supplémentaires via des API et met à jour l'interface utilisateur.
- Paramètres : Aucun.
- Retour : Aucun.

#### `filtrer_cves()`
- **Description** : Filtre les CVE critiques et les enregistre dans un fichier CSV. Met à jour l'interface utilisateur.
- **Paramètres** : Aucun.
- **Retour** : Aucun.

 `Envoi_emails()`
- Description : Envoie des notifications par email aux abonnés avec les détails des CVE critiques. Met à jour l'interface utilisateur.
- Paramètres : Aucun.
- Retour: Aucun.

`update_datetime()`
- Description: Met à jour l'affichage de la date et de l'heure dans l'interface utilisateur.
- Paramètres : Aucun.
- Retour: Aucun.

 `credit()`
-Description: Affiche une fenêtre de crédits avec les informations sur le développeur et la licence.
- Paramètres : Aucun.
- Retour : Aucun.

 `info()`
- Description : Affiche une fenêtre d'information avec des instructions et des avertissements pour l'utilisateur.
- Paramètres: Aucun.
- Retour: Aucun.

`close(event=None)`
- Description : Ferme l'application.
- Paramètres :
  - `event` : Événement déclencheur (optionnel).
- Retour : Aucun.

`check()`
- Description: Met à jour l'interface utilisateur périodiquement pour éviter les blocages.
- Paramètres : Aucun.
- Retour: Aucun.

 `bouton_email()`
- Description : Affiche une fenêtre permettant d'ajouter ou de retirer des abonnés à la liste de diffusion.
- Paramètres : Aucun.
- Retour: Aucun.

"""
import tkinter as tk #on commence par les import
from tkinter import messagebox, ttk
import feedparser
import requests
import re
from tqdm import tqdm
import pandas as pd
import os
import time
import unicodedata
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

url_avis = "https://www.cert.ssi.gouv.fr/avis/feed"  # on recup les url des feed avis & alertes 
url_alertes = "https://www.cert.ssi.gouv.fr/alerte/feed"

def rss(url, max_entries=100):
    rss_feed = feedparser.parse(url) #analyse 
    entrees = []
    for entry in rss_feed.entries[:max_entries]: # on parcout jusqu à le max e 100 entrees qu on a fixee
        entrees.append({
            "title": entry.title,
            "description": entry.description,
            "link": entry.link,
            "published": entry.published
        }) #on retourne à la liste
    return entrees

def CVES_Bulletins(json_url):
    try:
        reponse = requests.get(json_url, timeout=10) # on envoie un get  au json pour recup sa reponse 
        reponse.raise_for_status()
        data = reponse.json()
    except requests.RequestException as e:
        terminal_output.insert(tk.END, f"Erreur lors de la requête pour {json_url}: {e}\n") #catch l erreur pour comprendre le problème
        return [], []
    
    cves = [cve['name'] for cve in data.get("cves", [])] # on prends les naaaames des cve
    cve_pattern = r"CVE-\d{4}-\d{4,7}" #expression pour recup les identifiants CVE (CVE-YYYY-NNNN ou CVE-YYYY-NNNNNNN) merci l'ia 
    cve_liste = list(set(re.findall(cve_pattern, str(data))))#occurences
    
    return cves, cve_liste

def ENTREES(entries, type_bulletin, max_cve_per_entry=5):
    cve_data = []#on check les entres et on traite
    for entry in tqdm(entries, desc=f"Traitement des {type_bulletin.lower()}"):
        json_url = entry['link'] + "json/"
        ref_cves, cve_list = CVES_Bulletins(json_url)
        for cve_id in cve_list[:max_cve_per_entry]: #on limite pour eviter un trop long délais 
            cve_data.append({
                "title": entry['title'],
                "type_bulletin": type_bulletin,
                "published": entry['published'],
                "cve_id": cve_id,
                "link": entry['link']
            })
        terminal_output.insert(tk.END, f"Traitement des {type_bulletin.lower()}: {len(entries)} entrées traitées\n") # on affiche dans le terminal de la page 
        terminal_output.see(tk.END)
        root.update_idletasks()
    return cve_data

def CVEDETAILS(cve_id):# tout est dans le nom
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"# requete get pour url cve 
    try:
        reponse = requests.get(url, timeout=10)
        reponse.raise_for_status()
        data = reponse.json()
        
        if 'error' in data and data['error'] == "CVE_RECORD_DNE":
            terminal_output.insert(tk.END, "Erreur : une URL incorrecte détectée, correctif en cours...\n")#si url est incorrecte on protège le cod ( tres utile )
            return None

    except requests.RequestException as e:
        terminal_output.insert(tk.END, "Erreur : une URL incorrecte détectée, correctif en cours...\n") #affichage dans le te de la page 
        return None
# on initialiseeeeeeeeeeee par défauts
    description = "Non disponible"
    cvss_score = "Non disponible"
    cwe = "Non disponible"
    cwe_desc = "Non disponible"
    affected_products = []
    published_date = "Non disponible"

    if "containers" in data:
        containers = data["containers"]["cna"] # on accède à containers

        if "descriptions" in containers:
            description = containers["descriptions"][0]["value"]# recup descriptiopn

        try:
            cvss_score = containers["metrics"][0]["cvssV3_1"]["baseScore"]# recup cvss
        except KeyError:
            try:
                cvss_score = containers["metrics"][0]["cvssV3_0"]["baseScore"]#si le cvss 3.1 est pas dispo, on tente le 3.0
            except KeyError:
                pass
#cwe ( le fameux)
        problemetype = containers.get("problemTypes", [])
        if problemetype and "descriptions" in problemetype[0]:
            cwe = problemetype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc = problemetype[0]["descriptions"][0].get("description", "Non disponible")
#on recup les infos sur quels produits 
        affected = containers.get("affected", [])
        for product in affected:
            vendor = product.get("vendor", "Non disponible")
            product_nom = product.get("product", "Non disponible")
            versions = [v["version"] for v in product.get("versions", []) if v["status"] == "affected"]
            affected_products.append(f"Éditeur : {vendor}, Produit : {product_nom}, Versions : {', '.join(versions)}")
#alors ça je tente de recup la date mais je crois que ça marche pas à update 
        if "datePublic" in containers:
            published_date = containers["datePublic"]

    return {        #bah juste on retourne les détails des cve
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cwe": cwe,
        "cwe_desc": cwe_desc,
        "affected_products": affected_products,
        "published_date": published_date
    }

def EPSS_Score(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}" # on reup epss
    try:
        reponse = requests.get(url, timeout=10) # requet get à l url avec un petit timeout de 10s
        reponse.raise_for_status()
        data = reponse.json()
    except requests.RequestException as e:
        terminal_output.insert(tk.END, "Erreur : une URL incorrecte détectée, correctif en cours...\n")# on anticipe les erreurs
        return "Non disponible"

    epss_data = data.get("data", []) # on lit les dats de l epss
    if epss_data:
        epss_score = epss_data[0]["epss"] # on recup si on peut
    else:
        epss_score = "Non disponible" # sinon non 

    return epss_score

def NORMALISE(s):
    if not isinstance(s, str):# si chaine de caract 
        return s
    s = s.replace("'", " ")#apostrophe = espace
    s = ''.join(
        c for c in unicodedata.normalize('NFD', s) #on normalise pour retirr les accents 
        if unicodedata.category(c) != 'Mn'
    )
    return s

def DOUBLONS(s):
    if not isinstance(s, str):# si chaine de caract
        return s
    parts = s.split("; ") # on split comme c 'est ecrit 
    unique_part = list(dict.fromkeys(parts))#supp les doublons
    return "; ".join(unique_part)#rassemble les parties uniques

def MAJ(s):
    if not isinstance(s, str):#same ques les deux fct precedentes
        return s
    return s.replace("[MAJ] ", "") # mon cve afficher parfois des MAJ aléatoires, j'ai dev ça comme sécurité

def eemail(to_email, cc_email, subject, body):
    email = "anssi.noreply@gmail.com" # oui j ai crée une propre adresse mail dédié à l envoie des notifs quotidiennes pour rendre le projet plus réaliste 
    password = "lxdj mtum vjwb qirm"# code privé unique, ne pas perdre !!!! 
    msg = MIMEText(body, 'html') # on crée le mail
    msg['From'] = email
    msg['To'] = to_email
    msg['Cc'] = cc_email
    msg['Subject'] = subject
    try: # on utilise le server smtp de gmail
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(email, password)
        server.sendmail(email, [to_email, cc_email], msg.as_string())
        server.quit()
        print(f"Email envoyé à {to_email}")
    except Exception as e:  # on gere les porblemes avec des prints explicatifs 
        print(f"Erreur lors de l'envoi de l'email à {to_email}: {e}")

def extraire_rss():
    global avis_entree, alertes_entree
    avis_entree = rss(url_avis, max_entries=100) # on extrait le flux des avis et alertes avec un max d entrees 
    alertes_entree = rss(url_alertes, max_entries=100)
    progress_bar['value'] = 20 #maj de la barre globale, je vauis surement retirer car c est moche mais j'ai peur de tocuher au code il marche 
    root.update_idletasks()
    #message du terminal 
    terminal_output.insert(tk.END, f"Extraction des flux RSS terminée.\nNombre d'avis extraits: {len(avis_entree)}\nNombre d'alertes extraites: {len(alertes_entree)}\n")
    terminal_output.see(tk.END)
    root.update_idletasks()

def extraire_cves():
    global cve_data
    # on traites les entrées des avis et des alertes pour extraire les cvvee
    avis_cve_data = ENTREES(avis_entree, "Avis", max_cve_per_entry=5)
    alertes_cve_data = ENTREES(alertes_entree, "Alerte", max_cve_per_entry=5)
    cve_data = avis_cve_data + alertes_cve_data
    progress_bar['value'] = 40 # maj barre
    root.update_idletasks()
    #message terminall
    terminal_output.insert(tk.END, f"Extraction des CVE terminée.\nNombre de CVE extraits des avis: {len(avis_cve_data)}\nNombre de CVE extraits des alertes: {len(alertes_cve_data)}\n")
    terminal_output.see(tk.END)
    root.update_idletasks()

def enrichir_cves():
    # on rajouite des donnes pour enrichir les cve 
    for cve in tqdm(cve_data, desc="Enrichissement des CVE"):
        cve_details = CVEDETAILS(cve['cve_id'])
        if cve_details:
            cve.update(cve_details)
            cve['epss_score'] = EPSS_Score(cve['cve_id'])
    progress_bar['value'] = 60#maj barre
    root.update_idletasks()
    #same pour le te
    terminal_output.insert(tk.END, "Enrichissement des CVE terminé.\n")
    terminal_output.see(tk.END)
    root.update_idletasks()

def filtrer_cves():
    #on crée notre dataframe enfin !!!
    global df_filtered
    df = pd.DataFrame(cve_data, columns=[
        "title", "type_bulletin", "published", "cve_id", "cvss_score", 
        "cwe", "epss_score", "link", "description", 
        "affected_products"
    ])

    def determine_severity(cvss_score):
        try:
            #svérité du cve à cpartir du cvss 
            score = float(cvss_score)
            if score >= 9:
                return "Critique"
            elif score >= 7:
                return "Élevée"
            elif score >= 4:
                return "Moyenne"
            else:
                return "Faible"
        except ValueError:
            return "Non disponible"

    df['base_severity'] = df['cvss_score'].apply(determine_severity)

    def parse(affected_products):
        if not isinstance(affected_products, list):
            return {"vendor": "Non disponible", "product": "Non disponible", "versions": "Non disponible"}
        
        vendors = []
        products = []
        versions = []
        # on parse les infos des produits affectes 
        for product_info in affected_products:
            parts = product_info.split(", ")
            if len(parts) >= 3:
                vendor = parts[0].split(" : ")[1] if " : " in parts[0] else "Non disponible"
                product = parts[1].split(" : ")[1] if " : " in parts[1] else "Non disponible"
                version = parts[2].split(" : ")[1] if " : " in parts[2] else "Non disponible"
            else:
                vendor = "Non disponible"
                product = "Non disponible"
                version = "Non disponible"
            
            vendors.append(vendor)
            products.append(product)
            versions.append(version)
        
        return {
            "vendor": "; ".join(vendors),
            "product": "; ".join(products),
            "versions": "; ".join(versions)
    }
# on applique le parsing 
    parsed_products = df['affected_products'].apply(parse)
    df = df.join(pd.DataFrame(parsed_products.tolist()))
    df.drop(columns=['affected_products'], inplace=True)
    df = df.applymap(NORMALISE)
    df = df.applymap(DOUBLONS)
    df = df.applymap(MAJ)
    """alors petites explication ici, je voulais avoir les données les plus cohérentes possibles, donc j'ai dev une fonction 
    qui compte le nombre de données non disponibles par alertes/avis, et elle mets dans la datframe 
    en priorité ceux qui en ont le moins pour etre sur d avoir une base donnée la plus significative possible pour notre ase de donnée, je trouve le résultat très satisfaisant !! """
    df['non_disponible_count'] = df.apply(lambda row: sum(1 for value in row if value == "Non disponible"), axis=1)
    df_sorted = df.sort_values(by='non_disponible_count')
    initial_taille = 500
    df_initial_selection = df_sorted.head(initial_taille)
    max_cve = 125
    df_filtered = df_initial_selection.head(max_cve)
    df_filtered.drop(columns=['non_disponible_count'], inplace=True)
    df_filtered.to_csv('cve_data.csv', sep=';', index=False, mode='w', encoding='utf-8') #on sauvergare le cve
    progress_bar['value'] = 80#maj barre
    root.update_idletasks()
    # affichage termianle 
    terminal_output.insert(tk.END, f"Filtrage des CVE terminé.\nNombre total de CVE filtrés: {len(df_filtered)}\n")
    terminal_output.see(tk.END)
    root.update_idletasks()

def Envoi_emails():
    #on va recup les données du cve qui sont filtrés à partir du c
    df = pd.read_csv('cve_data.csv', sep=';')
    df['published'] = pd.to_datetime(df['published']).dt.tz_localize(None)
    df['cvss_score'] = pd.to_numeric(df['cvss_score'], errors='coerce')
    df['epss_score'] = pd.to_numeric(df['epss_score'], errors='coerce')
    critical_vulnerabilities = df[df['base_severity'] == 'Critique']

    
    start_date = datetime(2023, 1, 1)  
    days_ago = 3
    date_in_past = datetime.now() - timedelta(days=days_ago)
# je suis tres fiere de ma fonction mail, dans le code on ajoute des utilisateurs avec leurs mail leur nom et on personnalise leur notif en fonction de leur centre d interet et aussi de leur nom ! Fais le test d'envoyer un mail le rendu marche vraiment bien !!:
    for email, info in subscribers.items():
        name = info['name']
        products = info['products']
        body = f"""
        <h1>Bonjour {name},</h1>
        <p>Veuillez ne pas répondre (c'est vraiment idiot de le faire).</p>
        <p>Voici le résumé quotidien de vos alertes CVE :</p>
        <ul>
        """
        for product in products:
            product_vulnerabilite = critical_vulnerabilities[
                (critical_vulnerabilities['vendor'].str.contains(product, na=False)) &
                (critical_vulnerabilities['published'] >= start_date) &
                (critical_vulnerabilities['published'] <= date_in_past)
            ]
            if not product_vulnerabilite.empty:
                body += f"<li><strong>{product}</strong>:</li><ul>"
                for index, row in product_vulnerabilite.iterrows():
                    body += f"<li>{row['title']} (CVE: {row['cve_id']})<br>Score CVSS: {row['cvss_score']}<br>Description: {row['description']}<br>Lien: <a href='{row['link']}'>{row['link']}</a></li>"
                body += "</ul>"
        body += "</ul>"
        body += """
        <p>Merci pour votre confiance, en vous souhaitant une agréable vie.</p>
        <div style="text-align: center;">
            <pre style="font-family: monospace;">
             ____
           / . . \\
           \\  ---< 
            \\  /  
      ______/ /   
     /______/ /     
        </pre>
        <div style="text-align: center;">La Team Python</div>
        <hr>
        <p>En cas de difficulté, veuillez consulter notre centre d'assistance au +330783513028</p>
        """
        # on note le magnifique logo ascii genere par ia mais imagine par nous !! 
        eemail(email, "hugo.peltier@edu.devinci.fr", f"Alerte CVE critique pour {', '.join(products)}", body)
    progress_bar['value'] = 100
    root.update_idletasks()
    terminal_output.insert(tk.END, "Les emails ont été envoyés avec succès.\n")
    terminal_output.see(tk.END)
    root.update_idletasks()
    
root = tk.Tk()
root.title("Interface de Gestion des CVE")
root.configure(bg="#f0f0f0")  # Couleur de fond de la fenêtre principale

# liste des abonnés ( qui peut changer par la suite vous allez voir !!)
subscribers = {
    "hugo.peltier@edu.devinci.fr": {"name": "Hugo Peltier", "products": ["Apache", "Microsoft"]},
    "pichardlylou@gmail.com": {"name": "Lylou Pichard", "products": ["Cisco", "Fortinet"]},
}

# config de la grille principale 
root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=1)
root.grid_rowconfigure(2, weight=1)
root.grid_rowconfigure(3, weight=1)
root.grid_rowconfigure(4, weight=1)
root.grid_rowconfigure(5, weight=1)
root.grid_rowconfigure(6, weight=1)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_columnconfigure(2, weight=1)

# on créer des labels des labels pour acceulir date+heure
label_date = tk.Label(root, text="", font=("Helvetica", 12), bg="#f0f0f0", fg="#333333")
label_date.grid(row=0, column=0, padx=10, pady=10, sticky="nw")

# on utilise datetime pour afficher le temps en reél avec la date ( petite précision, lorsqu on lance une commande sur la page, elle peut se figer car l update ne peut pas gerer les deux appels )
def update_datetime():
    current_datetime = time.strftime("%Y-%m-%d %H:%M:%S")
    label_date.config(text=current_datetime)
    root.after(1000, update_datetime)

update_datetime()


#pour habiller u peu la page ( il veut pas se centrer jsp pourquoi)
esilv_frame = tk.Frame(root, bg="#f0f0f0")
esilv_frame.grid(row=0, column=1, padx=10, pady=10, sticky="ne")

esilv_logo = tk.Label(root, text="""
E S I L V    2 0 2 5
""", font=("Courier", 12), justify="center", bg="#f0f0f0", fg="#333333")
esilv_logo.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

#on créer unn cadre pour les boutons 
frame = tk.Frame(root, bg="#f0f0f0")
frame.grid(row=1, column=0, columnspan=3, pady=20, padx=20, sticky="nsew")

frame.grid_columnconfigure(0, weight=1)
frame.grid_columnconfigure(1, weight=1)
frame.grid_columnconfigure(2, weight=1)

# on associe les boutons à leurs fonctionnalités 
btn_extraire_rss = tk.Button(frame, text="Extraction des Flux RSS", command=extraire_rss, bg="#4CAF50", fg="white")
btn_extraire_rss.grid(row=0, column=1, pady=5, sticky="ew")

btn_extraire_cves = tk.Button(frame, text="Extraction des CVE", command=extraire_cves, bg="#4CAF50", fg="white")
btn_extraire_cves.grid(row=1, column=1, pady=5, sticky="ew")

btn_enrichir_cves = tk.Button(frame, text="Enrichissement des CVE", command=enrichir_cves, bg="#4CAF50", fg="white")
btn_enrichir_cves.grid(row=2, column=1, pady=5, sticky="ew")

btn_filtrer_cves = tk.Button(frame, text="Filtrage des CVE", command=filtrer_cves, bg="#4CAF50", fg="white")
btn_filtrer_cves.grid(row=3, column=1, pady=5, sticky="ew")

btn_Envoi_emails = tk.Button(frame, text="Envoi des Emails", command=Envoi_emails, bg="#4CAF50", fg="white")
btn_Envoi_emails.grid(row=4, column=1, pady=5, sticky="ew")

#zone de texte pour les messages 
terminal_output = tk.Text(root, height=15, width=100, bg="#ffffff", fg="#333333")
terminal_output.grid(row=2, column=0, columnspan=3, pady=20, sticky="nsew")

# variables pour les fnetres de credits et d informations
credits_window = None
info_window = None

def credit():
    global credits_window
    # verifie si la fnetre de credits est deja ouverte pour eviter qu on puisse en ouvir plusieurs 
    if credits_window is not None and tk.Toplevel.winfo_exists(credits_window):
        credits_window.lift()
        return

    # fenetre credit 
    credits_window = tk.Toplevel(root)
    credits_window.title("Crédits")
    credits_window.configure(bg="#ffebcd")

    frame = tk.Frame(credits_window, bg="#ffebcd")
    frame.pack(expand=True, fill="both")

    credits_label1 = tk.Label(frame, text="Crédits", font=("Arial", 16, "bold"), bg="#ffebcd", fg="#000080")
    credits_label1.pack(pady=(10, 0))

    credits_label2 = tk.Label(frame, text="Développé par Team Python", font=("Arial", 12, "bold"), bg="#ffebcd", fg="#000080")
    credits_label2.pack(pady=(0, 0))

    credits_label3 = tk.Label(frame, text="@Licence MIT", font=("Arial", 12, "bold"), bg="#ffebcd", fg="#000080")
    credits_label3.pack(pady=(0, 10))

    # credit texte, et oui on fait les choses bien !! 
    credits_text = """
    Permission est accordée, gratuitement, à toute personne obtenant une copie
    de ce logiciel et des fichiers de documentation associés (le "Logiciel"),
    de traiter le Logiciel sans restriction, y compris sans limitation les droits
    d'utiliser, de copier, de modifier, de fusionner, de publier, de distribuer,
    de sous-licencier et/ou de vendre des copies du Logiciel, et de permettre aux
    personnes à qui le Logiciel est fourni de le faire, sous réserve des conditions
    suivantes :

    La déclaration de copyright ci-dessus et cette permission doivent être incluses
    dans toutes les copies ou parties substantielles du Logiciel.

    LE LOGICIEL EST FOURNI "EN L'ÉTAT", SANS GARANTIE D'AUCUNE SORTE, EXPRESSE OU
    IMPLICITE, Y COMPRIS MAIS SANS S'Y LIMITER LES GARANTIES DE QUALITÉ MARCHANDE,
    D'ADÉQUATION À UN USAGE PARTICULIER ET D'ABSENCE DE CONTREFAÇON. EN AUCUN CAS,
    LES AUTEURS OU LES TITULAIRES DU COPYRIGHT NE POURRONT ÊTRE TENUS RESPONSABLES
    DE TOUTE RÉCLAMATION, DE DOMMAGES OU D'AUTRES RESPONSABILITÉS, QU'IL S'AGISSE
    D'UNE ACTION DE CONTRAT, DE DÉLIT OU AUTRE, DÉCOULANT DE, HORS OU EN RELATION
    AVEC LE LOGICIEL OU L'UTILISATION OU D'AUTRES TRAITEMENTS DANS LE LOGICIEL.
    """
    credits_text_widget = tk.Text(frame, font=("Arial", 12, "bold"), bg="#ffebcd", fg="#000080", wrap="word", padx=10, pady=10)
    credits_text_widget.insert(tk.END, credits_text)
    credits_text_widget.tag_configure("center", justify="center")
    credits_text_widget.tag_add("center", "1.0", "end")
    credits_text_widget.config(state=tk.DISABLED)
    credits_text_widget.pack(expand=True, fill="both")

def info():
    global info_window
    # verfie si la fenetre est deja ouverte 
    if info_window is not None and tk.Toplevel.winfo_exists(info_window):
        info_window.lift()
        return

    info_window = tk.Toplevel(root)
    info_window.title("Information")
    info_window.configure(bg="#ffebcd")

    #on l a créee 
    frame = tk.Frame(info_window, bg="#ffebcd")
    frame.pack(expand=True, fill="both")

    info_text = tk.Text(frame, font=("Arial", 12, "bold"), bg="#ffebcd", fg="#000080", wrap="word", padx=10, pady=10)
    info_text.insert(tk.END, """
    ⚠️ Attention ⚠️
Veuillez à ne pas utilisez des Wi-Fi publics/institutionnels, ils pourraient bloquer l'envoi des notifications.
Les suivis des processus se font dans le terminal de votre éditeur de code.
Vous avez accès à des barres de chargement qui vous indiquent le temps restant de chaque processus.
     |
     |
     |
     V
Merci de votre compréhension.
    """)
    info_text.tag_configure("center", justify="center")
    info_text.tag_add("center", "1.0", "end")
    info_text.config(state=tk.DISABLED)
    info_text.pack(expand=True, fill="both")

# bouton pour la fenetre d info 
info_button = tk.Button(root, text="i", command=info, bg="#4CAF50", fg="white")
info_button.grid(row=0, column=2, padx=10, pady=10, sticky="ne")

# on mets la barre de progression glkobale comme prevenu auparavant
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.grid(row=3, column=0, columnspan=3, pady=20, sticky="ew")

# boutons pour credits
credits_button = tk.Button(root, text="@", command=credit, bg="#4CAF50", fg="white")
credits_button.grid(row=3, column=2, padx=10, pady=10, sticky="se")

# affichage de notre logo crée de nopus meme ( c est fauxc c est une ia mais on a eu l idee)
logo_label = tk.Label(root, text="""
             ____
           / . . \\
           \\  ---< 
            \\  /  
      ______/ /   
     /______/ /    
""", font=("Courier", 12), justify="center", bg="#f0f0f0", fg="#333333")
logo_label.grid(row=4, column=0, columnspan=3, pady=20, sticky="nsew")

# afficher le nom d equipe
team_label = tk.Label(root, text="Team Python", font=("Helvetica", 16, "bold"), bg="#f0f0f0", fg="#333333")
team_label.grid(row=5, column=0, columnspan=3, pady=10, sticky="nsew")

def close(event=None):
    root.destroy()

root.bind('<s>', close) # raccourci clavier pour fermer la fenetre en cas de s presser 

def check():
    try:
        root.update()
        root.after(1000, check) # j ai fait ça car ma page plantait donc j ai decide de faire des updates mais ça n'a rien chnage, je la laisse en backup 
    except tk.TclError:
        close()

check()

# et voila ma grosse innovation !! vous avez la possibilité d ajouter des gens à notre newsletter, vous rentrez son adresse mail avec nom et ses centres dinterets !! j ai prevu bien sur des patchs si l utlisateur se trompe ( ne jamais lui faire confiance)
def bouton_email():
    email_window = tk.Toplevel(root)
    email_window.title("Ajouter ou Retirer une adresse e-mail")
    email_window.configure(bg="#f0f0f0")

    email_label = tk.Label(email_window, text="Adresse e-mail:", font=("Helvetica", 12), bg="#f0f0f0", fg="#333333")
    email_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")
    email_entry = tk.Entry(email_window, width=30)
    email_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

    name_label = tk.Label(email_window, text="Nom:", font=("Helvetica", 12), bg="#f0f0f0", fg="#333333")
    name_label.grid(row=1, column=0, padx=10, pady=5, sticky="e")
    name_entry = tk.Entry(email_window, width=30)
    name_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

    interests_label = tk.Label(email_window, text="Centres d'intérêt (séparés par des virgules):", font=("Helvetica", 12), bg="#f0f0f0", fg="#333333")
    interests_label.grid(row=2, column=0, padx=10, pady=5, sticky="e")
    interests_entry = tk.Entry(email_window, width=30)
    interests_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

    def add_email():
        email = email_entry.get()
        # on ajoute l adresse mail à la liste des abonnées 
        name = name_entry.get()
        interests = [interest.strip() for interest in interests_entry.get().split(',')]

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Erreur", "Adresse e-mail invalide.")
            return

        if not name:
            messagebox.showerror("Erreur", "Le nom ne peut pas être vide.")
            return

        if not interests:
            messagebox.showerror("Erreur", "Les centres d'intérêt ne peuvent pas être vides.")
            return

        subscribers[email] = {"name": name, "products": interests}
        print("Adresse e-mail ajoutée:", subscribers)

        email_entry.delete(0, tk.END)
        name_entry.delete(0, tk.END)
        interests_entry.delete(0, tk.END)

    def remove_email():
        # ou on peut retire son adresse mail pour ne plus recevoir les newsletter 
        email = email_entry.get()

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Erreur", "Adresse e-mail invalide.")
            return

        if email not in subscribers:
            messagebox.showerror("Erreur", "Adresse e-mail non trouvée.")
            return

        del subscribers[email]
        print("Adresse e-mail retirée:", email)

        email_entry.delete(0, tk.END)
        name_entry.delete(0, tk.END)
        interests_entry.delete(0, tk.END)

    # création du label pour le bouton ajouter une adresse mail 
    add_button = tk.Button(email_window, text="Ajouter l'adresse e-mail", command=add_email, bg="#4CAF50", fg="white")
    add_button.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

    # création du label pour le bouton retirer une adresse mail
    remove_button = tk.Button(email_window, text="Retirer l'adresse e-mail", command=remove_email, bg="#f44336", fg="white")
    remove_button.grid(row=3, column=1, padx=10, pady=10, sticky="ew")

# bouton pour la globalité ( ajouter ou retirer ou les deux si vous preferez )
bouton_email = tk.Button(root, text="Ajouter ou Retirer une adresse e-mail", command=bouton_email, bg="#4CAF50", fg="white")
bouton_email.grid(row=7, column=1, padx=10, pady=10, sticky="ew")

root.mainloop() 
# et on lance la boucle principale !!! 