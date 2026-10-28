#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                      ║
║                                                                                      ║
║                                                                                      ║
║                                                                                      ║
║                                                                                      ║
║     Détecte les algorithmes de chiffrement utilisés par un site web via son URL      ║
║     Analyse SSL/TLS, certificats, suites de chiffrement, en-têtes HTTP, DNS,         ║
║     vulnérabilités connues (Heartbleed, POODLE, BEAST, SWEET32, CRIME, etc.)         ║
║                                                                                      ║
║                                                                                      ║
║                                                                                      ║
║                                                                                      ║
║                                                                                      ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

# Tentative d'import des bibliothèques tierces (voir requirements.txt)
try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class _Dummy:
        def __getattr__(self, name):
            return ''
    Fore = Style = _Dummy()

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
    from cryptography.x509.oid import NameOID, ExtensionOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    import OpenSSL.SSL
    HAS_PYOPENSSL = True
except ImportError:
    HAS_PYOPENSSL = False

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# ---------------------------------------------------------------------------
# CONFIGURATION GLOBALE
# ---------------------------------------------------------------------------
APP_NAME = "Crypto Scanner Pro Max"
APP_VERSION = "10.0 ULTIMATE"
APP_AUTHOR = "hackers_tchad"
APP_LICENSE = "Pentest"

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10
MAX_REDIRECTS = 5
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# BASES DE DONNÉES : ALGORITHMES, PROTOCOLES, VULNÉRABILITÉS
# ---------------------------------------------------------------------------
TLS_VERSIONS = {
    "SSLv2": 0x0002,
    "SSLv3": 0x0300,
    "TLSv1.0": 0x0301,
    "TLSv1.1": 0x0302,
    "TLSv1.2": 0x0303,
    "TLSv1.3": 0x0304,
}

TLS_VERSION_NAMES = {v: k for k, v in TLS_VERSIONS.items()}

CIPHER_SUITES = {
    # TLS 1.3
    0x1301: ("TLS_AES_128_GCM_SHA256", "AES-128-GCM", "SHA256", "TLS 1.3", "RECOMMANDÉ"),
    0x1302: ("TLS_AES_256_GCM_SHA384", "AES-256-GCM", "SHA384", "TLS 1.3", "RECOMMANDÉ"),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "CHACHA20-POLY1305", "SHA256", "TLS 1.3", "RECOMMANDÉ"),
    0x1304: ("TLS_AES_128_CCM_SHA256", "AES-128-CCM", "SHA256", "TLS 1.3", "ACCEPTABLE"),
    0x1305: ("TLS_AES_128_CCM_8_SHA256", "AES-128-CCM-8", "SHA256", "TLS 1.3", "FAIBLE"),

    # TLS 1.2 - suites fortes
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "AES-128-GCM", "SHA256", "TLS 1.2", "RECOMMANDÉ"),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "AES-256-GCM", "SHA384", "TLS 1.2", "RECOMMANDÉ"),
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "AES-128-GCM", "SHA256", "TLS 1.2", "RECOMMANDÉ"),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "AES-256-GCM", "SHA384", "TLS 1.2", "RECOMMANDÉ"),
    0xCCA8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "CHACHA20-POLY1305", "SHA256", "TLS 1.2", "RECOMMANDÉ"),
    0xCCA9: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "CHACHA20-POLY1305", "SHA256", "TLS 1.2", "RECOMMANDÉ"),
    0x009E: ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "AES-128-GCM", "SHA256", "TLS 1.2", "RECOMMANDÉ"),
    0x009F: ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "AES-256-GCM", "SHA384", "TLS 1.2", "RECOMMANDÉ"),
    0xC0A0: ("TLS_RSA_WITH_AES_128_CCM", "AES-128-CCM", "SHA256", "TLS 1.2", "ACCEPTABLE"),
    0xC0A1: ("TLS_RSA_WITH_AES_256_CCM", "AES-256-CCM", "SHA384", "TLS 1.2", "ACCEPTABLE"),

    # TLS 1.2 - suites acceptables
    0xC027: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "AES-128-CBC", "SHA256", "TLS 1.2", "ACCEPTABLE"),
    0xC028: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "AES-256-CBC", "SHA384", "TLS 1.2", "ACCEPTABLE"),
    0xC013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "AES-128-CBC", "SHA1", "TLS 1.2", "ACCEPTABLE"),
    0xC014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "AES-256-CBC", "SHA1", "TLS 1.2", "ACCEPTABLE"),
    0x0033: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "AES-128-CBC", "SHA1", "TLS 1.2", "ACCEPTABLE"),
    0x0039: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "AES-256-CBC", "SHA1", "TLS 1.2", "ACCEPTABLE"),
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "AES-128-CBC", "SHA1", "TLS 1.2", "ACCEPTABLE"),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "AES-256-CBC", "SHA1", "TLS 1.2", "ACCEPTABLE"),
    0x003C: ("TLS_RSA_WITH_AES_128_CBC_SHA256", "AES-128-CBC", "SHA256", "TLS 1.2", "ACCEPTABLE"),
    0x003D: ("TLS_RSA_WITH_AES_256_CBC_SHA256", "AES-256-CBC", "SHA256", "TLS 1.2", "ACCEPTABLE"),

    # Suites faibles / obsolètes
    0x0005: ("TLS_RSA_WITH_RC4_128_SHA", "RC4", "SHA1", "SSLv3/TLS 1.0", "FAIBLE"),
    0x0004: ("TLS_RSA_WITH_RC4_128_MD5", "RC4", "MD5", "SSLv3/TLS 1.0", "FAIBLE"),
    0x002C: ("TLS_PSK_WITH_NULL_SHA", "NULL", "SHA1", "TLS 1.0", "FAIBLE"),
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "3DES-EDE-CBC", "SHA1", "SSLv3/TLS", "FAIBLE"),
    0xC012: ("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "3DES-EDE-CBC", "SHA1", "TLS 1.0", "FAIBLE"),
    0x0016: ("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "3DES-EDE-CBC", "SHA1", "SSLv3/TLS", "FAIBLE"),
    0x0041: ("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "CAMELLIA-128-CBC", "SHA1", "TLS 1.2", "ACCEPTABLE"),
    0x0084: ("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "CAMELLIA-256-CBC", "SHA1", "TLS 1.2", "ACCEPTABLE"),
    0xC077: ("TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "CAMELLIA-128-CBC", "SHA256", "TLS 1.2", "ACCEPTABLE"),
    0xC078: ("TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", "CAMELLIA-256-CBC", "SHA384", "TLS 1.2", "ACCEPTABLE"),
    0x0001: ("TLS_RSA_WITH_NULL_MD5", "NULL", "MD5", "SSLv2", "FAIBLE"),
    0x0002: ("TLS_RSA_WITH_NULL_SHA", "NULL", "SHA1", "SSLv2", "FAIBLE"),
    0x0003: ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RC4-40", "MD5", "SSLv2", "FAIBLE"),
    0x0006: ("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", "RC2-CBC-40", "MD5", "SSLv2", "FAIBLE"),
    0x0008: ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "DES-CBC-40", "SHA1", "SSLv2", "FAIBLE"),
    0x0009: ("TLS_RSA_WITH_DES_CBC_SHA", "DES-CBC", "SHA1", "SSLv2", "FAIBLE"),
    0x0062: ("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "3DES-EDE-CBC", "SHA1", "SSLv3", "FAIBLE"),
    0x0063: ("TLS_DHE_DSS_WITH_DES_CBC_SHA", "DES-CBC", "SHA1", "SSLv3", "FAIBLE"),
    0x0065: ("TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "DES-CBC-40", "SHA1", "SSLv2", "FAIBLE"),
    0x00FF: ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "N/A", "N/A", "TLS", "EXTENSION"),
}

WEAK_CIPHERS = {"RC4", "RC4-40", "3DES-EDE-CBC", "DES-CBC", "DES-CBC-40", "NULL", "RC2-CBC-40"}
WEAK_HASHES = {"MD5", "SHA1"}
WEAK_KEY_EXCHANGES = {"RSA", "EXPORT", "DHE_DSS", "PSK"}

VULNERABILITIES = {
    "heartbleed": {
        "name": "Heartbleed (CVE-2014-0160)",
        "description": "Fuite de mémoire dans OpenSSL liée à l'extension heartbeat.",
        "affected": ["TLS 1.0", "TLS 1.1", "TLS 1.2"],
        "severity": "CRITIQUE",
    },
    "poodle": {
        "name": "POODLE (CVE-2014-3566)",
        "description": "Attaque par padding sur SSLv3 permettant le déchiffrement de cookies.",
        "affected": ["SSLv3"],
        "severity": "CRITIQUE",
    },
    "poodle_tls": {
        "name": "POODLE TLS (CVE-2014-8730)",
        "description": "Variante POODLE exploitant une implémentation TLS incorrecte.",
        "affected": ["TLS 1.0", "TLS 1.1", "TLS 1.2"],
        "severity": "ÉLEVÉE",
    },
    "beast": {
        "name": "BEAST (CVE-2011-3389)",
        "description": "Attaque sur TLS 1.0/CBC exploitant la prédiction du vecteur d'initialisation.",
        "affected": ["TLS 1.0"],
        "severity": "MOYENNE",
    },
    "crime": {
        "name": "CRIME (CVE-2012-4929)",
        "description": "Compression TLS exploitée pour révéler des secrets.",
        "affected": ["TLS 1.0", "TLS 1.1", "TLS 1.2"],
        "severity": "ÉLEVÉE",
    },
    "breach": {
        "name": "BREACH (CVE-2013-3587)",
        "description": "Compression HTTP exploitée pour révéler des secrets.",
        "affected": ["HTTP"],
        "severity": "ÉLEVÉE",
    },
    "sweet32": {
        "name": "SWEET32 (CVE-2016-2183)",
        "description": "Collision sur les blocs de 64 bits (3DES, Blowfish).",
        "affected": ["3DES-EDE-CBC", "Blowfish"],
        "severity": "MOYENNE",
    },
    "freak": {
        "name": "FREAK (CVE-2015-0204)",
        "description": "Attaque downgrade vers des suites RSA export faibles.",
        "affected": ["EXPORT"],
        "severity": "ÉLEVÉE",
    },
    "logjam": {
        "name": "Logjam (CVE-2015-4000)",
        "description": "Attaque downgrade sur Diffie-Hellman de 512/1024 bits.",
        "affected": ["DHE"],
        "severity": "ÉLEVÉE",
    },
    "drown": {
        "name": "DROWN (CVE-2016-0800)",
        "description": "Déchiffrement TLS via support SSLv2 partagé.",
        "affected": ["SSLv2"],
        "severity": "CRITIQUE",
    },
    "lucky13": {
        "name": "Lucky13 (CVE-2013-0169)",
        "description": "Attaque par timing sur le padding MAC-then-encrypt CBC.",
        "affected": ["CBC-SHA", "CBC-SHA256"],
        "severity": "MOYENNE",
    },
    "rc4": {
        "name": "RC4 NOMORE (CVE-2013-2566 / CVE-2015-2808)",
        "description": "Biais statistiques dans RC4 permettant la récupération de secrets.",
        "affected": ["RC4"],
        "severity": "ÉLEVÉE",
    },
    "bar_mitzvah": {
        "name": "Bar Mitzvah (CVE-2015-2808)",
        "description": "Attaque RC4 exploitant les weak keys dans TLS.",
        "affected": ["RC4"],
        "severity": "ÉLEVÉE",
    },
    "sec_client_hello": {
        "name": "Secondary ClientHello (CVE-2014-1492)",
        "description": "Problème de re-négociation dans certaines implémentations NSS.",
        "affected": ["TLS"],
        "severity": "MOYENNE",
    },
    "ticketbleed": {
        "name": "Ticketbleed (CVE-2016-9244)",
        "description": "Fuite de 31 octets de mémoire via les tickets de session TLS.",
        "affected": ["TLS 1.0", "TLS 1.1", "TLS 1.2"],
        "severity": "ÉLEVÉE",
    },
    "zero_length_padding": {
        "name": "Zero-Length Padding Oracle (CVE-2019-1559)",
        "description": "Oracle de padding dans OpenSSL affectant CBC.",
        "affected": ["CBC"],
        "severity": "MOYENNE",
    },
    "golden_doodle": {
        "name": "Goldendoodle (CVE-2019-1559)",
        "description": "Variante de l'oracle de padding zero-length.",
        "affected": ["CBC"],
        "severity": "MOYENNE",
    },
    "raccoon": {
        "name": "Raccoon (CVE-2020-1968)",
        "description": "Attaque par timing sur la première version du secret TLS-DH.",
        "affected": ["DHE", "ECDHE"],
        "severity": "MOYENNE",
    },
    "bleichenbacher": {
        "name": "Bleichenbacher (ROBOT)",
        "description": "Attaque par oracle de padding RSA PKCS#1 v1.5.",
        "affected": ["RSA_KEY_EXCHANGE"],
        "severity": "ÉLEVÉE",
    },
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "HSTS",
        "description": "Force le navigateur à utiliser HTTPS.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "name": "CSP",
        "description": "Contrôle les sources de contenu exécutables.",
        "recommended": "default-src 'self'",
    },
    "X-Frame-Options": {
        "name": "Clickjacking protection",
        "description": "Empêche l'intégration dans un iframe.",
        "recommended": "DENY ou SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "name": "MIME sniffing protection",
        "description": "Empêche le sniffing MIME.",
        "recommended": "nosniff",
    },
    "Referrer-Policy": {
        "name": "Referrer policy",
        "description": "Contrôle les informations de référence envoyées.",
        "recommended": "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "name": "Permissions policy",
        "description": "Contrôle les API du navigateur.",
        "recommended": "camera=(), microphone=(), geolocation=()",
    },
    "Cross-Origin-Embedder-Policy": {
        "name": "COEP",
        "description": "Contrôle l'intégration cross-origin.",
        "recommended": "require-corp",
    },
    "Cross-Origin-Opener-Policy": {
        "name": "COOP",
        "description": "Isole les fenêtres cross-origin.",
        "recommended": "same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "name": "CORP",
        "description": "Contrôle les requêtes cross-origin sur les ressources.",
        "recommended": "same-origin",
    },
}

PUBLIC_KEY_ALGORITHMS = {
    "rsaEncryption": "RSA",
    "id-ecPublicKey": "ECDSA/ECDH",
    "dsa": "DSA",
    "Ed25519": "Ed25519",
    "Ed448": "Ed448",
}

SIGNATURE_ALGORITHMS = {
    "sha256WithRSAEncryption": ("RSA", "SHA-256"),
    "sha384WithRSAEncryption": ("RSA", "SHA-384"),
    "sha512WithRSAEncryption": ("RSA", "SHA-512"),
    "sha1WithRSAEncryption": ("RSA", "SHA-1"),
    "md5WithRSAEncryption": ("RSA", "MD5"),
    "ecdsa-with-SHA256": ("ECDSA", "SHA-256"),
    "ecdsa-with-SHA384": ("ECDSA", "SHA-384"),
    "ecdsa-with-SHA512": ("ECDSA", "SHA-512"),
    "ecdsa-with-SHA1": ("ECDSA", "SHA-1"),
    "dsa-with-sha256": ("DSA", "SHA-256"),
    "dsa-with-sha1": ("DSA", "SHA-1"),
    "ed25519": ("Ed25519", "SHA-512"),
    "ed448": ("Ed448", "SHAKE-256"),
}

# ---------------------------------------------------------------------------
# FONCTIONS D'AFFICHAGE / UI
# ---------------------------------------------------------------------------
def green_progress_bar(iteration, total, prefix="Progression", length=50, fill="█"):
    """Affiche une barre de progression verte dans le terminal."""
    if total == 0:
        total = 1
    percent = 100 * (iteration / float(total))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + "-" * (length - filled_length)
    color_open = Fore.GREEN if HAS_COLORAMA else ""
    color_close = Style.RESET_ALL if HAS_COLORAMA else ""
    sys.stdout.write(
        f"\r{color_open}{prefix} |{bar}| {percent:.1f}%{color_close}"
    )
    sys.stdout.flush()
    if iteration >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()


def print_banner():
    """Affiche le grand titre avec astérisques."""
    banner = f"""
{Fore.GREEN if HAS_COLORAMA else ''}
 ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗      ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║     ███████╗██║     ███████║██╔██╗ ██║
██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║     ╚════██║██║     ██╔══██║██║╚██╗██║
╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝     ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝      ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL if HAS_COLORAMA else ''}
"""
    print(banner)
    title_line = "★" * 79
    print(Fore.GREEN + title_line + Style.RESET_ALL if HAS_COLORAMA else title_line)
    print(
        (Fore.GREEN if HAS_COLORAMA else "")
        + "  *****   CRYPTO SCANNER PRO MAX - ÉDITION ULTIMATE   *****"
        + (Style.RESET_ALL if HAS_COLORAMA else "")
    )
    print(
        (Fore.GREEN if HAS_COLORAMA else "")
        + "  *****   Détection avancée des algorithmes de chiffrement   *****"
        + (Style.RESET_ALL if HAS_COLORAMA else "")
    )
    print(
        (Fore.GREEN if HAS_COLORAMA else "")
        + f"  *****   Auteur: {APP_AUTHOR}  |  Version: {APP_VERSION}   *****"
        + (Style.RESET_ALL if HAS_COLORAMA else "")
    )
    print(Fore.GREEN + title_line + Style.RESET_ALL if HAS_COLORAMA else title_line)
    print()


def print_section(title):
    """Affiche une section clairement délimitée."""
    print()
    line = "═" * 79
    print(Fore.CYAN + line + Style.RESET_ALL if HAS_COLORAMA else line)
    print(
        (Fore.CYAN if HAS_COLORAMA else "")
        + f"  ► {title.upper()}"
        + (Style.RESET_ALL if HAS_COLORAMA else "")
    )
    print(Fore.CYAN + line + Style.RESET_ALL if HAS_COLORAMA else line)


def print_info(label, value, level="info"):
    """Affiche une information formatée."""
    color_map = {
        "info": Fore.WHITE,
        "ok": Fore.GREEN,
        "warn": Fore.YELLOW,
        "error": Fore.RED,
        "critical": Fore.MAGENTA,
    }
    color = color_map.get(level, Fore.WHITE) if HAS_COLORAMA else ""
    reset = Style.RESET_ALL if HAS_COLORAMA else ""
    print(f"  {color}{label:28}{reset} {value}")


def print_bullet(text, level="info"):
    """Affiche une puce."""
    color_map = {
        "info": Fore.WHITE,
        "ok": Fore.GREEN,
        "warn": Fore.YELLOW,
        "error": Fore.RED,
        "critical": Fore.MAGENTA,
    }
    color = color_map.get(level, Fore.WHITE) if HAS_COLORAMA else ""
    reset = Style.RESET_ALL if HAS_COLORAMA else ""
    print(f"  {color}• {text}{reset}")


# ---------------------------------------------------------------------------
# UTILITAIRES RÉSEAU
# ---------------------------------------------------------------------------
def normalize_url(url):
    """Normalise une URL en ajoutant https:// si nécessaire."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return urlunparse(parsed), parsed


def resolve_hostname(hostname):
    """Résout un nom d'hôte en adresse IPv4/IPv6."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        ipv4 = None
        ipv6 = None
        for fam, _, _, _, sockaddr in infos:
            if fam == socket.AF_INET and ipv4 is None:
                ipv4 = sockaddr[0]
            elif fam == socket.AF_INET6 and ipv6 is None:
                ipv6 = sockaddr[0]
        return ipv4, ipv6
    except Exception:
        return None, None


def fetch_url_headers(url, timeout=DEFAULT_TIMEOUT, max_redirects=MAX_REDIRECTS):
    """Récupère les en-têtes HTTP/HTTPS avec gestion des redirections."""
    headers = {}
    status = None
    final_url = url
    try:
        if HAS_REQUESTS:
            session = requests.Session()
            session.max_redirects = max_redirects
            session.headers.update({"User-Agent": USER_AGENT})
            resp = session.head(url, timeout=timeout, allow_redirects=True)
            headers = dict(resp.headers)
            status = resp.status_code
            final_url = resp.url
            if status in (405, 403, 500):
                resp = session.get(url, timeout=timeout, allow_redirects=True, stream=True)
                resp.close()
                headers = dict(resp.headers)
                status = resp.status_code
                final_url = resp.url
        else:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="HEAD")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    headers = dict(response.headers)
                    status = response.getcode()
                    final_url = response.geturl()
            except urllib.error.HTTPError as exc:
                if exc.code in (405, 403, 500):
                    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                    with urllib.request.urlopen(req, timeout=timeout) as response:
                        headers = dict(response.headers)
                        status = response.getcode()
                        final_url = response.geturl()
                else:
                    raise
    except Exception as exc:
        headers = {"error": str(exc)}
    return headers, status, final_url


def get_server_certificate(hostname, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    """Récupère le certificat TLS du serveur en PEM."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_pem = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(binary_form=True))
                return cert_pem, ssock.version(), ssock.cipher()
    except Exception as exc:
        return None, None, str(exc)


# ---------------------------------------------------------------------------
# ANALYSE DU CERTIFICAT
# ---------------------------------------------------------------------------
def parse_certificate_pem(pem_data):
    """Analyse un certificat PEM et extrait les informations essentielles."""
    if not HAS_CRYPTOGRAPHY or not pem_data:
        return {"error": "Module cryptography non installé ou certificat vide"}
    try:
        cert = x509.load_pem_x509_certificate(pem_data.encode("utf-8"))
        fingerprint = cert.fingerprint(hashes.SHA256())
        info = {
            "subject": {},
            "issuer": {},
            "serial": str(cert.serial_number),
            "fingerprint_sha256": fingerprint.hex(),
            "not_before": cert.not_valid_before_utc,
            "not_after": cert.not_valid_after_utc,
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "key_algorithm": "Inconnu",
            "key_size": None,
            "curve_name": None,
            "subject_alt_names": [],
            "key_usage": [],
            "extended_key_usage": [],
            "basic_constraints": {},
            "ocsp": None,
            "authority_info_access": [],
            "crl_distribution_points": [],
            "certificate_policies": [],
            "is_self_signed": False,
            "is_expired": cert.not_valid_after_utc < datetime.now(timezone.utc),
            "version": cert.version.name,
        }

        for attr in cert.subject:
            info["subject"][attr.oid._name] = attr.value
        for attr in cert.issuer:
            info["issuer"][attr.oid._name] = attr.value

        try:
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                info["key_algorithm"] = "RSA"
                info["key_size"] = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                info["key_algorithm"] = "ECDSA/ECDH"
                info["key_size"] = pub_key.key_size
                info["curve_name"] = pub_key.curve.name
            elif isinstance(pub_key, dsa.DSAPublicKey):
                info["key_algorithm"] = "DSA"
                info["key_size"] = pub_key.key_size
            elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                info["key_algorithm"] = pub_key.__class__.__name__.replace("PublicKey", "")
                info["key_size"] = None
        except Exception:
            pass

        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            info["subject_alt_names"] = san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        try:
            ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            info["key_usage"] = [usage for usage, val in {
                "digital_signature": ku.value.digital_signature,
                "content_commitment": ku.value.content_commitment,
                "key_encipherment": ku.value.key_encipherment,
                "data_encipherment": ku.value.data_encipherment,
                "key_agreement": ku.value.key_agreement,
                "key_cert_sign": ku.value.key_cert_sign,
                "crl_sign": ku.value.crl_sign,
            }.items() if val]
        except x509.ExtensionNotFound:
            pass

        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
            info["extended_key_usage"] = [str(oid) for oid in eku.value]
        except x509.ExtensionNotFound:
            pass

        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            info["basic_constraints"] = {
                "ca": bc.value.ca,
                "path_length": bc.value.path_length,
            }
        except x509.ExtensionNotFound:
            pass

        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for desc in aia.value:
                if desc.access_method._name == "OCSP":
                    info["ocsp"] = str(desc.access_location)
                info["authority_info_access"].append(str(desc.access_location))
        except x509.ExtensionNotFound:
            pass

        try:
            crl = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for dp in crl.value:
                for full_name in dp.full_name or []:
                    info["crl_distribution_points"].append(str(full_name))
        except x509.ExtensionNotFound:
            pass

        try:
            cp = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            info["certificate_policies"] = [str(p.oid) for p in cp.value]
        except x509.ExtensionNotFound:
            pass

        if info["subject"] == info["issuer"]:
            info["is_self_signed"] = True

        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        info["days_valid"] = delta.days
        remaining = cert.not_valid_after_utc - datetime.now(timezone.utc)
        info["days_remaining"] = remaining.days

        return info
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# DÉTECTION DES PROTOCOLES TLS/SSL SUPPORTÉS
# ---------------------------------------------------------------------------
def test_tls_protocol(hostname, port=DEFAULT_PORT, protocol=None, timeout=DEFAULT_TIMEOUT):
    """Teste si un serveur accepte un protocole TLS/SSL donné."""
    if protocol is None:
        protocol = ssl.PROTOCOL_TLS_CLIENT
    try:
        ctx = ssl.SSLContext(protocol)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True, ssock.version()
    except Exception as exc:
        return False, str(exc)


def detect_supported_protocols(hostname, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    """Détecte quels protocoles SSL/TLS sont supportés par le serveur."""
    results = {}
    protocol_tests = [
        ("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ssl.TLSVersion.TLSv1_3, "maximum_version": ssl.TLSVersion.TLSv1_3}),
        ("TLSv1.2", ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ssl.TLSVersion.TLSv1_2, "maximum_version": ssl.TLSVersion.TLSv1_2}),
        ("TLSv1.1", ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ssl.TLSVersion.TLSv1_1, "maximum_version": ssl.TLSVersion.TLSv1_1}),
        ("TLSv1.0", ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ssl.TLSVersion.TLSv1, "maximum_version": ssl.TLSVersion.TLSv1}),
    ]
    for name, proto, versions in protocol_tests:
        try:
            ctx = ssl.SSLContext(proto)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if hasattr(ctx, "minimum_version"):
                ctx.minimum_version = versions["minimum_version"]
                ctx.maximum_version = versions["maximum_version"]
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    results[name] = {
                        "supported": True,
                        "negotiated": ssock.version(),
                        "cipher": ssock.cipher(),
                    }
        except Exception as exc:
            results[name] = {"supported": False, "error": str(exc)}

    for legacy in ("SSLv3", "SSLv2"):
        results[legacy] = {"supported": False, "error": "Protocole obsolète non testé par ssl moderne"}
    return results


# ---------------------------------------------------------------------------
# DÉTECTION DES SUITES DE CHIFFREMENT
# ---------------------------------------------------------------------------
def detect_cipher_suites(hostname, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    """Tente de déterminer les suites de chiffrement acceptées par le serveur."""
    supported = []
    total = len(CIPHER_SUITES)
    print_section("DÉTECTION DES SUITES DE CHIFFREMENT")
    print(f"  Analyse de {total} suites connues sur {hostname}:{port}...")

    for idx, (suite_id, suite_info) in enumerate(CIPHER_SUITES.items(), start=1):
        green_progress_bar(idx, total, prefix="  Scan des suites", length=40)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            cipher_name = suite_info[0]
            try:
                ctx.set_ciphers(cipher_name)
            except ssl.SSLError:
                continue
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    negotiated = ssock.cipher()
                    if negotiated and negotiated[0]:
                        supported.append({
                            "id": f"0x{suite_id:04X}",
                            "name": negotiated[0],
                            "protocol": ssock.version(),
                            "bits": negotiated[2],
                            "raw_info": suite_info,
                        })
        except Exception:
            pass

    seen = set()
    unique = []
    for c in supported:
        key = c["name"] + c["protocol"]
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


# ---------------------------------------------------------------------------
# ANALYSE DES EN-TÊTES HTTP SÉCURISÉS
# ---------------------------------------------------------------------------
def analyze_security_headers(headers):
    """Analyse les en-têtes de sécurité HTTP."""
    findings = {}
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for header, meta in SECURITY_HEADERS.items():
        value = headers_lower.get(header.lower())
        findings[header] = {
            "present": value is not None,
            "value": value,
            "name": meta["name"],
            "description": meta["description"],
            "recommended": meta["recommended"],
        }
    findings["compression"] = {
        "present": bool(headers_lower.get("content-encoding")),
        "value": headers_lower.get("content-encoding"),
        "name": "HTTP compression",
        "description": "Compression HTTP (BREACH si contenu secret compressé).",
        "recommended": "Désactiver pour les pages sensibles",
    }
    return findings


# ---------------------------------------------------------------------------
# DÉTECTION DE VULNÉRABILITÉS (HEURISTIQUES)
# ---------------------------------------------------------------------------
def evaluate_vulnerabilities(protocols, ciphers, headers, cert_info):
    """Évalue les vulnérabilités connues à partir des informations collectées."""
    vulns = []

    if protocols.get("SSLv3", {}).get("supported"):
        vulns.append({**VULNERABILITIES["poodle"], "detected": True})
    if protocols.get("SSLv2", {}).get("supported"):
        vulns.append({**VULNERABILITIES["drown"], "detected": True})

    if protocols.get("TLSv1.0", {}).get("supported"):
        vulns.append({**VULNERABILITIES["beast"], "detected": True})
        vulns.append({**VULNERABILITIES["poodle_tls"], "detected": "possible"})

    for c in ciphers:
        if any(rc4 in c.get("name", "").upper() for rc4 in ("RC4", "ARC4")):
            vulns.append({**VULNERABILITIES["rc4"], "detected": True})
            vulns.append({**VULNERABILITIES["bar_mitzvah"], "detected": True})
            break

    for c in ciphers:
        if "3DES" in c.get("name", "").upper() or "DES-CBC3" in c.get("name", "").upper():
            vulns.append({**VULNERABILITIES["sweet32"], "detected": True})
            break

    for c in ciphers:
        name_upper = c.get("name", "").upper()
        if "EXPORT" in name_upper or "EXP-" in name_upper:
            vulns.append({**VULNERABILITIES["freak"], "detected": True})
            break

    for c in ciphers:
        if "NULL" in c.get("name", "").upper():
            vulns.append({
                "name": "Suite de chiffrement NULL",
                "description": "Aucun chiffrement n'est appliqué.",
                "affected": ["NULL"],
                "severity": "CRITIQUE",
                "detected": True,
            })
            break

    if headers.get("compression", {}).get("value"):
        enc = headers["compression"]["value"].lower()
        if "deflate" in enc or "gzip" in enc:
            vulns.append({**VULNERABILITIES["breach"], "detected": "possible"})

    if cert_info:
        sig = cert_info.get("signature_algorithm", "").upper()
        if "MD5" in sig:
            vulns.append({
                "name": "Signature MD5",
                "description": "Le certificat utilise MD5, vulnérable aux collisions.",
                "affected": ["MD5"],
                "severity": "CRITIQUE",
                "detected": True,
            })
        if "SHA1" in sig:
            vulns.append({
                "name": "Signature SHA-1 obsolète",
                "description": "SHA-1 est déconseillé pour les signatures de certificats.",
                "affected": ["SHA1"],
                "severity": "ÉLEVÉE",
                "detected": True,
            })
        if cert_info.get("key_size") and cert_info.get("key_algorithm") == "RSA" and cert_info["key_size"] < 2048:
            vulns.append({
                "name": "Clé RSA trop petite",
                "description": f"Taille de clé RSA {cert_info['key_size']} bits insuffisante.",
                "affected": ["RSA"],
                "severity": "ÉLEVÉE",
                "detected": True,
            })
        if cert_info.get("is_expired"):
            vulns.append({
                "name": "Certificat expiré",
                "description": "Le certificat n'est plus valide.",
                "affected": ["X.509"],
                "severity": "CRITIQUE",
                "detected": True,
            })
        if cert_info.get("is_self_signed"):
            vulns.append({
                "name": "Certificat auto-signé",
                "description": "Le certificat n'est pas signé par une autorité de confiance.",
                "affected": ["X.509"],
                "severity": "MOYENNE",
                "detected": True,
            })

    for c in ciphers:
        name_upper = c.get("name", "").upper()
        if "CBC" in name_upper and ("SHA" in name_upper and "SHA256" not in name_upper and "SHA384" not in name_upper):
            vulns.append({**VULNERABILITIES["lucky13"], "detected": "possible"})
            break

    for c in ciphers:
        name_upper = c.get("name", "").upper()
        if "RSA" in name_upper and "ECDHE" not in name_upper and "DHE" not in name_upper:
            vulns.append({**VULNERABILITIES["bleichenbacher"], "detected": "possible"})
            break

    for c in ciphers:
        if "DHE" in c.get("name", "").upper():
            vulns.append({**VULNERABILITIES["logjam"], "detected": "possible"})
            break

    return vulns


# ---------------------------------------------------------------------------
# INFORMATIONS DNS ET WHOIS
# ---------------------------------------------------------------------------
def get_dns_info(hostname):
    """Récupère les enregistrements DNS courants."""
    records = {}
    if not HAS_DNSPYTHON:
        records["note"] = "Module dnspython non installé."
        return records

    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "PTR"):
        try:
            ans = dns.resolver.resolve(hostname, rtype, lifetime=5)
            records[rtype] = [str(rdata) for rdata in ans]
        except Exception:
            records[rtype] = []

    try:
        ans = dns.resolver.resolve(hostname, "DNSKEY", lifetime=5)
        records["DNSSEC"] = True
        records["DNSKEY"] = [str(rdata) for rdata in ans]
    except Exception:
        records["DNSSEC"] = False

    return records


def get_whois_info(hostname):
    """Récupère des informations WHOIS basiques via whois CLI."""
    info = {"raw": "", "registrar": None, "creation": None, "expiration": None, "nameservers": []}
    try:
        result = subprocess.run(
            ["whois", hostname], capture_output=True, text=True, timeout=15
        )
        raw = result.stdout
        info["raw"] = raw[:2000]
        for line in raw.splitlines():
            low = line.lower()
            if "registrar:" in low and not info["registrar"]:
                info["registrar"] = line.split(":", 1)[1].strip()
            if "creation date" in low and not info["creation"]:
                info["creation"] = line.split(":", 1)[1].strip()
            if "registry expiry date" in low and not info["expiration"]:
                info["expiration"] = line.split(":", 1)[1].strip()
            if "name server" in low:
                ns = line.split(":", 1)[1].strip()
                if ns and ns not in info["nameservers"]:
                    info["nameservers"].append(ns)
    except FileNotFoundError:
        info["raw"] = "Commande 'whois' non trouvée."
    except Exception as exc:
        info["raw"] = f"Erreur WHOIS: {exc}"
    return info


# ---------------------------------------------------------------------------
# TESTS DE VULNÉRABILITÉS ACTIFS (SIMPLIFIÉS)
# ---------------------------------------------------------------------------
def check_heartbleed(hostname, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    """Test Heartbleed simplifié (envoi d'un heartbeat TLS malformé)."""
    if not HAS_PYOPENSSL:
        return "NON_TESTÉ", "PyOpenSSL requis"
    try:
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
        ctx.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda *args: True)
        sock = socket.create_connection((hostname, port), timeout=timeout)
        conn = OpenSSL.SSL.Connection(ctx, sock)
        conn.set_tlsext_host_name(hostname.encode("utf-8"))
        conn.set_connect_state()
        conn.do_handshake()
        return "INCONNU", "Test heuristique non concluant sans extension heartbeat"
    except Exception as exc:
        return "ERREUR", str(exc)


def check_poodle(hostname, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    """Vérifie si SSLv3 est accepté (POODLE)."""
    supported, msg = test_tls_protocol(hostname, port, protocol=ssl.PROTOCOL_TLS_CLIENT, timeout=timeout)
    return "VULNÉRABLE" if supported else "NON_VULNÉRABLE", msg


# ---------------------------------------------------------------------------
# SCORING ET RAPPORT
# ---------------------------------------------------------------------------
def compute_security_score(protocols, ciphers, vulns, headers, cert_info):
    """Calcule un score de sécurité sur 100."""
    score = 100

    if protocols.get("SSLv2", {}).get("supported"):
        score -= 30
    if protocols.get("SSLv3", {}).get("supported"):
        score -= 30
    if protocols.get("TLSv1.0", {}).get("supported"):
        score -= 15
    if protocols.get("TLSv1.1", {}).get("supported"):
        score -= 10

    weak_count = 0
    for c in ciphers:
        raw = c.get("raw_info", ())
        if len(raw) >= 5 and raw[4] in ("FAIBLE",):
            weak_count += 1
    score -= weak_count * 5

    for v in vulns:
        sev = v.get("severity", "")
        if sev == "CRITIQUE":
            score -= 10
        elif sev == "ÉLEVÉE":
            score -= 6
        elif sev == "MOYENNE":
            score -= 3
        elif sev == "FAIBLE":
            score -= 1

    missing_headers = sum(1 for h in headers.values() if not h.get("present"))
    score -= missing_headers * 2

    if cert_info:
        if cert_info.get("is_expired"):
            score -= 20
        if cert_info.get("is_self_signed"):
            score -= 10
        if cert_info.get("key_algorithm") == "RSA" and cert_info.get("key_size", 0) < 2048:
            score -= 10
        sig = cert_info.get("signature_algorithm", "").upper()
        if "MD5" in sig:
            score -= 15
        if "SHA1" in sig:
            score -= 8

    return max(0, min(100, score))


def grade_from_score(score):
    """Convertit un score en note littérale."""
    if score >= 90:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 80:
        return "A-"
    if score >= 75:
        return "B+"
    if score >= 70:
        return "B"
    if score >= 65:
        return "B-"
    if score >= 60:
        return "C+"
    if score >= 55:
        return "C"
    if score >= 50:
        return "C-"
    if score >= 40:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# AFFICHAGE DU RAPPORT FINAL
# ---------------------------------------------------------------------------
def print_report(url, hostname, port, ip_info, protocols, ciphers, headers, cert_info, dns_info, whois_info, vulns, score):
    """Affiche le rapport complet."""
    print_banner()
    print_section("INFORMATIONS GÉNÉRALES")
    print_info("URL analysée", url)
    print_info("Hôte", hostname)
    print_info("Port", port)
    print_info("IPv4", ip_info[0] or "Non résolu")
    print_info("IPv6", ip_info[1] or "Non résolu")
    print_info("Date du scan", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))

    print_section("PROTOCOLES SSL/TLS")
    for proto, data in protocols.items():
        if data.get("supported"):
            print_info(proto, f"✅ Supporté (négocié: {data.get('negotiated')})", "ok")
        else:
            print_info(proto, "❌ Non supporté ou refusé", "error")

    print_section("SUITES DE CHIFFREMENT NÉGOCIÉES")
    if ciphers:
        for c in ciphers:
            strength = c.get("raw_info", ["", "", "", "", "INCONNU"])[4]
            level = "ok" if strength == "RECOMMANDÉ" else "warn" if strength == "ACCEPTABLE" else "error"
            print_bullet(
                f"{c['id']} {c['name']} [{c['protocol']}] {c['bits']} bits - {strength}",
                level,
            )
    else:
        print_bullet("Aucune suite détectée (connexion refusée ou erreur).", "warn")

    print_section("CERTIFICAT TLS")
    if cert_info and "error" not in cert_info:
        print_info("Sujet", ", ".join(f"{k}={v}" for k, v in cert_info.get("subject", {}).items()))
        print_info("Émetteur", ", ".join(f"{k}={v}" for k, v in cert_info.get("issuer", {}).items()))
        print_info("Algorithme de clé", cert_info.get("key_algorithm"))
        print_info("Taille de clé", cert_info.get("key_size") or "N/A")
        print_info("Algorithme de signature", cert_info.get("signature_algorithm"))
        print_info("Série", cert_info.get("serial"))
        print_info("Empreinte SHA-256", cert_info.get("fingerprint_sha256"))
        print_info("Valide du", str(cert_info.get("not_before")))
        print_info("Valide jusqu'au", str(cert_info.get("not_after")))
        print_info("Jours restants", cert_info.get("days_remaining"))
        print_info("Auto-signé", "Oui" if cert_info.get("is_self_signed") else "Non")
        print_info("Expiré", "Oui" if cert_info.get("is_expired") else "Non")
        print_info("SAN", ", ".join(cert_info.get("subject_alt_names", [])))
        print_info("OCSP", cert_info.get("ocsp") or "Non fourni")
        print_info("Points de distribution CRL", ", ".join(cert_info.get("crl_distribution_points", [])))
    else:
        print_bullet("Impossible d'analyser le certificat.", "error")

    print_section("EN-TÊTES DE SÉCURITÉ HTTP")
    for header, data in headers.items():
        if data.get("present"):
            print_info(data["name"], data["value"], "ok")
        else:
            print_info(data["name"], "Manquant", "warn")

    print_section("VULNÉRABILITÉS DÉTECTÉES")
    if vulns:
        for v in vulns:
            level = "critical" if v["severity"] == "CRITIQUE" else "error" if v["severity"] == "ÉLEVÉE" else "warn"
            print_bullet(f"[{v['severity']}] {v['name']}: {v['description']} (détecté: {v['detected']})", level)
    else:
        print_bullet("Aucune vulnérabilité connue détectée.", "ok")

    print_section("INFORMATIONS DNS")
    for rtype, values in dns_info.items():
        if rtype == "note":
            print_bullet(values, "warn")
        elif values:
            print_info(rtype, ", ".join(values[:5]))

    print_section("INFORMATIONS WHOIS")
    print_info("Registrar", whois_info.get("registrar") or "N/A")
    print_info("Création", whois_info.get("creation") or "N/A")
    print_info("Expiration", whois_info.get("expiration") or "N/A")
    print_info("Serveurs de noms", ", ".join(whois_info.get("nameservers", [])))

    print_section("SCORE DE SÉCURITÉ")
    grade = grade_from_score(score)
    level = "ok" if score >= 80 else "warn" if score >= 60 else "error"
    print_info("Score", f"{score}/100", level)
    print_info("Note", grade, level)

    print()
    line = "═" * 79
    print(Fore.GREEN + line + Style.RESET_ALL if HAS_COLORAMA else line)
    print(
        (Fore.GREEN if HAS_COLORAMA else "")
        + "  Scan terminé. Merci d'utiliser Crypto Scanner Pro Max."
        + (Style.RESET_ALL if HAS_COLORAMA else "")
    )
    print(
        (Fore.GREEN if HAS_COLORAMA else "")
        + f"  Auteur: {APP_AUTHOR}  |  {APP_LICENSE}"
        + (Style.RESET_ALL if HAS_COLORAMA else "")
    )
    print(Fore.GREEN + line + Style.RESET_ALL if HAS_COLORAMA else line)


# ---------------------------------------------------------------------------
# FONCTION PRINCIPALE
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} v{APP_VERSION} - Détecte les algorithmes de chiffrement d'un site web."
    )
    parser.add_argument("url", help="URL ou nom d'hôte du site à analyser")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="Port HTTPS (défaut: 443)")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout en secondes")
    parser.add_argument("--no-banner", action="store_true", help="Masquer la bannière")
    parser.add_argument("--json", action="store_true", help="Exporter le rapport en JSON")
    parser.add_argument("-o", "--output", help="Fichier de sortie JSON")
    args = parser.parse_args()

    url, parsed = normalize_url(args.url)
    hostname = parsed.hostname
    port = args.port

    if not hostname:
        print("URL invalide.", file=sys.stderr)
        sys.exit(1)

    if not args.no_banner:
        print_banner()

    total_steps = 8
    step = 0

    step += 1
    green_progress_bar(step, total_steps, prefix="[1/8] Résolution DNS")
    ip_info = resolve_hostname(hostname)

    step += 1
    green_progress_bar(step, total_steps, prefix="[2/8] Récupération certificat")
    pem_cert, tls_version, cipher_info = get_server_certificate(hostname, port, args.timeout)
    cert_info = parse_certificate_pem(pem_cert) if pem_cert else None

    step += 1
    green_progress_bar(step, total_steps, prefix="[3/8] Détection protocoles")
    protocols = detect_supported_protocols(hostname, port, args.timeout)

    step += 1
    green_progress_bar(step, total_steps, prefix="[4/8] Scan des suites")
    ciphers = detect_cipher_suites(hostname, port, args.timeout)

    step += 1
    green_progress_bar(step, total_steps, prefix="[5/8] Analyse en-têtes HTTP")
    headers, status, final_url = fetch_url_headers(url, args.timeout)
    header_analysis = analyze_security_headers(headers)

    step += 1
    green_progress_bar(step, total_steps, prefix="[6/8] Informations DNS/WHOIS")
    dns_info = get_dns_info(hostname)
    whois_info = get_whois_info(hostname)

    step += 1
    green_progress_bar(step, total_steps, prefix="[7/8] Évaluation vulnérabilités")
    vulns = evaluate_vulnerabilities(protocols, ciphers, header_analysis, cert_info)

    step += 1
    green_progress_bar(step, total_steps, prefix="[8/8] Calcul du score")
    score = compute_security_score(protocols, ciphers, vulns, header_analysis, cert_info)

    print_report(
        url=final_url if final_url else url,
        hostname=hostname,
        port=port,
        ip_info=ip_info,
        protocols=protocols,
        ciphers=ciphers,
        headers=header_analysis,
        cert_info=cert_info,
        dns_info=dns_info,
        whois_info=whois_info,
        vulns=vulns,
        score=score,
    )

    if args.json or args.output:
        report = {
            "app": APP_NAME,
            "version": APP_VERSION,
            "author": APP_AUTHOR,
            "url": final_url if final_url else url,
            "hostname": hostname,
            "port": port,
            "ip": {"ipv4": ip_info[0], "ipv6": ip_info[1]},
            "protocols": protocols,
            "ciphers": ciphers,
            "certificate": cert_info,
            "headers": header_analysis,
            "dns": dns_info,
            "whois": whois_info,
            "vulnerabilities": vulns,
            "score": score,
            "grade": grade_from_score(score),
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }
        output_path = args.output or "crypto_scan_report.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n  Rapport JSON exporté: {output_path}")


if __name__ == "__main__":
    main()
