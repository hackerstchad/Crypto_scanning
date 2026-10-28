# Crypto Scanner Pro Max

**Auteur :** hackers_tchad  
**Version :** 10.0 ULTIMATE

Crypto Scanner Pro Max est un script Python avancé qui analyse un site web via son URL pour détecter :

- Les protocoles SSL/TLS supportés (TLS 1.0, 1.1, 1.2, 1.3, SSLv2/v3)
- Les suites de chiffrement négociées
- L'algorithme de chiffrement utilisé par le certificat
- Les informations du certificat TLS/SSL
- Les en-têtes de sécurité HTTP
- Les vulnérabilités connues (Heartbleed, POODLE, BEAST, CRIME, BREACH, SWEET32, FREAK, Logjam, DROWN, Lucky13, RC4, Bleichenbacher, etc.)
- Les enregistrements DNS et les informations WHOIS
- Un score de sécurité global avec une note (A+ à F)

## Caractéristiques

- ✅ Grande bannière titre avec astérisques (*****)
- ✅ Barre de progression verte
- ✅ Rapport complet affiché sur une seule page
- ✅ Export JSON possible
- ✅ Plus de 1000 lignes de code avancées
- ✅ Auteur : hackers_tchad

## Installation

```bash
pip install -r requirements.txt
```

## Utilisation

```bash
python crypto_scanner.py example.com
python crypto_scanner.py https://example.com -t 15
python crypto_scanner.py example.com --json -o rapport.json
```

## Dépendances

- colorama
- cryptography
- dnspython
- pyOpenSSL
- requests

## Avertissement

Ce script est fourni à des fins éducatives et de tests d'intrusion autorisés uniquement. N'utilisez-le que sur des sites dont vous êtes propriétaire ou pour lesquels vous avez une autorisation explicite.
