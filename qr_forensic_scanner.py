#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                       QR CODE FORENSIC SCANNER v1.0                            ║
║                              NEATLABS ™                                        ║
║          Advanced QR Code Analysis • Payload Forensics • Threat Detection      ║
╚══════════════════════════════════════════════════════════════════════════════════╝

Enterprise-grade QR code forensic analysis tool for cybersecurity professionals.

CAPABILITIES:
  • Multi-engine QR/barcode decoding (OpenCV + libzbar)
  • Payload type identification (URL, WiFi, vCard, Crypto, SMS, Email, etc.)
  • Phishing & malicious URL detection with 50+ heuristic indicators
  • QR code structural analysis (version, ECC level, mask pattern, modules)
  • Image forensic analysis (stego indicators, EXIF metadata, manipulation detection)
  • Multi-QR overlay/poisoning detection
  • Comprehensive threat scoring with risk assessment
  • Professional HTML report generation with visual analysis
  • Full GUI + CLI interface

USAGE:
  python3 qr_forensic_scanner.py                           # Launch GUI
  python3 qr_forensic_scanner.py <image_file>              # Scan single QR (CLI)
  python3 qr_forensic_scanner.py <directory>               # Batch scan (CLI)
  python3 qr_forensic_scanner.py <image> --report out.html # Custom report path
  python3 qr_forensic_scanner.py <image> --json            # JSON output
  python3 qr_forensic_scanner.py --demo                    # Generate demo QR + scan

SUPPORTED FORMATS: PNG, JPG, JPEG, BMP, GIF, TIFF, WEBP

Author: NEATLABS
License: Proprietary — All Rights Reserved
"""

import sys, os, re, json, hashlib, base64, struct, math, time
import argparse, io, urllib.parse, ipaddress, threading
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter, defaultdict
from typing import Optional, Dict, List, Tuple, Any

import numpy as np
import cv2
from PIL import Image, ImageDraw, ImageFont
from PIL.ExifTags import TAGS as EXIF_TAGS

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"
TOOL_NAME = "QR Code Forensic Scanner"
BRAND = "NEATLABS"

ECC_LEVELS = {
    0: {"name": "L (Low)", "recovery": "~7%", "risk": "Low tampering resistance"},
    1: {"name": "M (Medium)", "recovery": "~15%", "risk": "Moderate tampering resistance"},
    2: {"name": "Q (Quartile)", "recovery": "~25%", "risk": "Good tampering resistance"},
    3: {"name": "H (High)", "recovery": "~30%", "risk": "High tampering resistance — may indicate intentional data hiding"},
}

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.click', '.link',
    '.buzz', '.rest', '.surf', '.monster', '.icu', '.cam', '.quest',
    '.beauty', '.hair', '.skin', '.boats', '.sbs', '.cfd',
    '.autos', '.motorcycles', '.yachts',
}

PHISHING_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'secure', 'account', 'update',
    'confirm', 'banking', 'paypal', 'apple', 'microsoft', 'google', 'amazon',
    'netflix', 'facebook', 'instagram', 'whatsapp', 'telegram',
    'wallet', 'crypto', 'bitcoin', 'ethereum', 'airdrop', 'claim',
    'prize', 'winner', 'reward', 'gift', 'free', 'bonus', 'offer',
    'password', 'credential', 'ssn', 'social-security',
    'suspend', 'locked', 'unauthorized', 'unusual', 'limited',
    'urgent', 'immediate', 'action-required', 'expire',
    'invoice', 'payment', 'receipt', 'billing', 'refund',
]

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc',
    'rb.gy', 'qr.codes', 'v.gd', 'x.co', 'linktr.ee', 'dub.sh',
    'short.io', 'bl.ink', 'snip.ly', 'clck.ru', 'clicky.me',
}

CRYPTO_PATTERNS = {
    'bitcoin': r'^(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})$',
    'ethereum': r'^0x[0-9a-fA-F]{40}$',
    'monero': r'^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$',
    'litecoin': r'^(L[a-km-zA-HJ-NP-Z1-9]{26,33}|M[a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-zA-HJ-NP-Z0-9]{25,90})$',
    'ripple': r'^r[0-9a-zA-Z]{24,34}$',
    'dogecoin': r'^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$',
    'bitcoin_cash': r'^(bitcoincash:)?[qp][a-z0-9]{41}$',
    'solana': r'^[1-9A-HJ-NP-Za-km-z]{32,44}$',
}

WIFI_SECURITY = {
    'WPA3': {'rating': 'Strong', 'color': '#22c55e', 'notes': 'Current best practice'},
    'WPA2': {'rating': 'Adequate', 'color': '#84cc16', 'notes': 'Still acceptable if properly configured'},
    'WPA': {'rating': 'Weak', 'color': '#f59e0b', 'notes': 'Deprecated — vulnerable to TKIP attacks'},
    'WEP': {'rating': 'Critical', 'color': '#ef4444', 'notes': 'Trivially crackable — must upgrade immediately'},
    'nopass': {'rating': 'None', 'color': '#ef4444', 'notes': 'Open network — all traffic visible to attackers'},
}

COLORS = {
    'bg_dark': '#0a0e1a', 'bg_mid': '#111827', 'bg_card': '#1a2332',
    'bg_input': '#0f1629', 'border': '#2a3a4a', 'accent': '#3b82f6',
    'accent_hover': '#2563eb', 'text': '#e2e8f0', 'text_secondary': '#94a3b8',
    'text_muted': '#64748b', 'green': '#22c55e', 'yellow': '#f59e0b',
    'orange': '#f97316', 'red': '#ef4444', 'critical': '#dc2626',
    'purple': '#a855f7', 'cyan': '#06b6d4', 'white': '#ffffff',
}


# ═══════════════════════════════════════════════════════════════════════════════
# LIBZBAR CTYPES WRAPPER
# ═══════════════════════════════════════════════════════════════════════════════

class ZBarDecoder:
    def __init__(self):
        self.available = False
        try:
            import ctypes, ctypes.util
            lib_path = ctypes.util.find_library('zbar')
            if lib_path:
                self._zbar = ctypes.CDLL(lib_path)
                self.available = True
        except Exception:
            pass

    def decode(self, image):
        if not self.available:
            return []
        import ctypes
        results = []
        try:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
            h, w = gray.shape
            scanner = self._zbar.zbar_image_scanner_create()
            self._zbar.zbar_image_scanner_set_config(scanner, 0, 0, 1)
            zimg = self._zbar.zbar_image_create()
            self._zbar.zbar_image_set_format(zimg, int.from_bytes(b'Y800', 'little'))
            self._zbar.zbar_image_set_size(zimg, w, h)
            data = gray.tobytes()
            self._zbar.zbar_image_set_data(zimg, ctypes.c_char_p(data), len(data), None)
            n = self._zbar.zbar_scan_image(scanner, zimg)
            if n > 0:
                self._zbar.zbar_image_first_symbol.restype = ctypes.c_void_p
                self._zbar.zbar_symbol_next.restype = ctypes.c_void_p
                self._zbar.zbar_symbol_get_data.restype = ctypes.c_char_p
                self._zbar.zbar_symbol_get_type.restype = ctypes.c_int
                self._zbar.zbar_get_symbol_name.restype = ctypes.c_char_p
                sym = self._zbar.zbar_image_first_symbol(zimg)
                while sym:
                    d = self._zbar.zbar_symbol_get_data(sym)
                    if d:
                        results.append({'data': d.decode('utf-8', errors='replace'), 'type': 'QR-Code', 'engine': 'libzbar'})
                    sym = self._zbar.zbar_symbol_next(sym)
            self._zbar.zbar_image_destroy(zimg)
            self._zbar.zbar_image_scanner_destroy(scanner)
        except Exception:
            pass
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# QR DECODER ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class QRDecoder:
    def __init__(self):
        self.cv2_det = cv2.QRCodeDetector()
        self.zbar = ZBarDecoder()

    def decode_all(self, image_path):
        img = cv2.imread(image_path)
        if img is None:
            try:
                img = cv2.cvtColor(np.array(Image.open(image_path).convert('RGB')), cv2.COLOR_RGB2BGR)
            except:
                return {'error': f'Cannot read: {image_path}', 'codes': []}
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        res = {'codes': [], 'multi_qr_detected': False, 'overlay_risk': False,
               'image_dimensions': (img.shape[1], img.shape[0]), 'engines_used': []}

        cv2_codes = []
        try:
            d, p, s = self.cv2_det.detectAndDecode(gray)
            if d and p is not None:
                cv2_codes.append({'data': d, 'points': p[0].tolist(), 'engine': 'opencv'})
            ret, di, pa, sc = self.cv2_det.detectAndDecodeMulti(gray)
            if ret and di:
                for i, dd in enumerate(di):
                    if dd and not any(c['data'] == dd for c in cv2_codes):
                        cv2_codes.append({'data': dd, 'points': pa[i].tolist() if pa is not None else None, 'engine': 'opencv'})
            if cv2_codes:
                res['engines_used'].append('opencv')
        except Exception:
            pass

        zbar_codes = self.zbar.decode(img)
        if zbar_codes:
            res['engines_used'].append('libzbar')

        seen = set()
        for c in cv2_codes + zbar_codes:
            if c['data'] not in seen:
                seen.add(c['data'])
                res['codes'].append(c)

        if len(res['codes']) > 1:
            res['multi_qr_detected'] = True
            res['overlay_risk'] = True

        if not res['codes']:
            for method in [self._thresh, self._adaptive, self._invert, self._scale]:
                proc = method(gray)
                if proc is not None:
                    try:
                        d, p, _ = self.cv2_det.detectAndDecode(proc)
                        if d:
                            res['codes'].append({'data': d, 'points': p[0].tolist() if p is not None else None, 'engine': f'opencv+enhanced'})
                            break
                    except:
                        pass
        return res

    def _thresh(self, g):
        _, t = cv2.threshold(g, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU); return t
    def _adaptive(self, g):
        return cv2.adaptiveThreshold(g, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
    def _invert(self, g):
        return cv2.bitwise_not(g)
    def _scale(self, g):
        h, w = g.shape
        if max(h, w) < 500:
            s = 500 / max(h, w)
            return cv2.resize(g, None, fx=s, fy=s, interpolation=cv2.INTER_CUBIC)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# QR STRUCTURAL ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class QRStructuralAnalyzer:
    @staticmethod
    def analyze(image_path, decode_result):
        img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            try: img = np.array(Image.open(image_path).convert('L'))
            except: return {}

        a = {'finder_patterns': [], 'estimated_version': None, 'estimated_ecc': None,
             'module_size_px': None, 'quiet_zone_adequate': None, 'rotation_degrees': 0}

        fps = QRStructuralAnalyzer._find_fps(img)
        a['finder_patterns'] = fps

        if len(fps) >= 3:
            ms = np.mean([f['size'] for f in fps]) / 7.0
            a['module_size_px'] = round(ms, 2)

            if decode_result.get('codes'):
                dl = len(decode_result['codes'][0].get('data', ''))
                for thresh, ver in [(25,'1-2 (21-25 modules)'),(78,'3-5 (29-37 modules)'),
                                     (154,'6-9 (41-53 modules)'),(370,'10-15 (57-77 modules)'),
                                     (858,'16-25 (81-117 modules)')]:
                    if dl <= thresh:
                        a['estimated_version'] = ver; break
                else:
                    a['estimated_version'] = '26-40 (121-177 modules)'

            # Quiet zone check
            req = int(ms * 4); h, w = img.shape
            xs = [f['center'][0] for f in fps]; ys = [f['center'][1] for f in fps]
            sz = max(f['size'] for f in fps)
            a['quiet_zone_adequate'] = all(m >= req for m in [min(xs)-sz, w-max(xs)-sz, min(ys)-sz, h-max(ys)-sz])

            if len(fps) >= 2:
                p1, p2 = fps[0]['center'], fps[1]['center']
                a['rotation_degrees'] = round(math.degrees(math.atan2(p2[1]-p1[1], p2[0]-p1[0])), 1)

        if decode_result.get('codes') and a['module_size_px'] and a['module_size_px'] > 0:
            dl = len(decode_result['codes'][0].get('data', '').encode('utf-8'))
            mods = (img.shape[0] * img.shape[1]) / (a['module_size_px'] ** 2)
            cr = dl / max(mods, 1)
            for thresh, lvl in [(0.05, 3), (0.10, 2), (0.15, 1)]:
                if cr < thresh:
                    a['estimated_ecc'] = ECC_LEVELS[lvl]; break
            else:
                a['estimated_ecc'] = ECC_LEVELS[0]

        return a

    @staticmethod
    def _find_fps(gray):
        patterns = []
        _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        contours, hierarchy = cv2.findContours(binary, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
        if hierarchy is None: return patterns
        hierarchy = hierarchy[0]
        for i, (c, h) in enumerate(zip(contours, hierarchy)):
            if h[2] != -1 and hierarchy[h[2]][2] != -1:
                area = cv2.contourArea(c)
                if area > 100:
                    x, y, w, hr = cv2.boundingRect(c)
                    if 0.7 < w/max(hr,1) < 1.3:
                        M = cv2.moments(c)
                        if M['m00'] > 0:
                            patterns.append({'center': (int(M['m10']/M['m00']), int(M['m01']/M['m00'])),
                                           'size': max(w, hr), 'area': area})
        patterns.sort(key=lambda p: p['area'], reverse=True)
        return patterns[:3]


# ═══════════════════════════════════════════════════════════════════════════════
# PAYLOAD ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class PayloadAnalyzer:
    @staticmethod
    def analyze(raw_data):
        result = {'raw_data': raw_data, 'data_length': len(raw_data),
                  'encoding': PayloadAnalyzer._detect_enc(raw_data),
                  'payload_type': 'unknown', 'payload_details': {},
                  'threat_indicators': [], 'threat_score': 0,
                  'risk_level': 'UNKNOWN', 'iocs': [],
                  'entropy': PayloadAnalyzer._entropy(raw_data)}
        pt, det = PayloadAnalyzer._classify(raw_data)
        result['payload_type'] = pt; result['payload_details'] = det
        threats = PayloadAnalyzer._threats(raw_data, pt, det)
        result['threat_indicators'] = threats['indicators']
        result['threat_score'] = threats['score']
        result['risk_level'] = threats['level']
        result['iocs'] = threats['iocs']
        return result

    @staticmethod
    def _detect_enc(data):
        enc = {'is_utf8': True, 'has_unicode': any(ord(c) > 127 for c in data),
               'has_control_chars': any(ord(c) < 32 and c not in '\n\r\t' for c in data),
               'is_base64': False, 'is_hex': False,
               'printable_ratio': sum(1 for c in data if c.isprintable()) / max(len(data), 1)}
        if len(data) > 20 and re.match(r'^[A-Za-z0-9+/]+=*$', data.strip()):
            try:
                base64.b64decode(data.strip()); enc['is_base64'] = True
            except: pass
        if len(data) > 10 and len(data) % 2 == 0 and re.match(r'^[0-9a-fA-F]+$', data.strip()):
            enc['is_hex'] = True
        return enc

    @staticmethod
    def _entropy(data):
        if not data: return 0.0
        c = Counter(data); n = len(data)
        return round(-sum((v/n)*math.log2(v/n) for v in c.values()), 4)

    @staticmethod
    def _classify(data):
        d = data.strip(); dl = d.lower()
        if re.match(r'^https?://', d, re.I): return 'url', PayloadAnalyzer._parse_url(d)
        if d.startswith('WIFI:'): return 'wifi', PayloadAnalyzer._parse_wifi(d)
        if d.startswith('BEGIN:VCARD'): return 'vcard', PayloadAnalyzer._parse_vcard(d)
        if dl.startswith('mailto:'): return 'email', {'email': d[7:].split('?')[0]}
        if dl.startswith(('smsto:','sms:','mmsto:','mms:')): return 'sms', {'number': d.split(':',1)[1].split('?')[0]}
        if dl.startswith('tel:'): return 'phone', {'number': d[4:]}
        if dl.startswith('geo:'): return 'geo', {'raw': d}
        if d.startswith('BEGIN:VEVENT'): return 'calendar', {'raw': d}
        cr = PayloadAnalyzer._check_crypto(d)
        if cr: return 'cryptocurrency', cr
        if d.startswith('MECARD:'): return 'mecard', {'raw': d}
        if dl.startswith('otpauth://'): return 'otp_auth', PayloadAnalyzer._parse_otp(d)
        if re.match(r'^[\w.-]+\.\w{2,}(/\S*)?$', d):
            return 'url_no_schema', {'raw': d, 'implied_url': f'http://{d}'}
        return 'plaintext', {'text': d, 'word_count': len(d.split())}

    @staticmethod
    def _parse_url(url):
        p = urllib.parse.urlparse(url)
        det = {'full_url': url, 'scheme': p.scheme, 'domain': p.hostname or '', 'port': p.port,
               'path': p.path, 'query': p.query, 'query_params': dict(urllib.parse.parse_qs(p.query)),
               'url_length': len(url), 'subdomain_count': 0,
               'is_ip_address': False, 'is_shortened': False, 'has_suspicious_tld': False,
               'redirect_params': [], 'encoded_segments': []}
        dom = det['domain']
        try: ipaddress.ip_address(dom); det['is_ip_address'] = True
        except: pass
        if dom and not det['is_ip_address']:
            det['subdomain_count'] = max(0, len(dom.split('.')) - 2)
        if dom in URL_SHORTENERS: det['is_shortened'] = True
        for tld in SUSPICIOUS_TLDS:
            if dom.endswith(tld): det['has_suspicious_tld'] = True; break
        for k, vs in det['query_params'].items():
            for v in vs:
                if re.match(r'https?://', v): det['redirect_params'].append({'param': k, 'target': v})
        if '%' in url:
            dec = urllib.parse.unquote(url)
            if dec != url: det['encoded_segments'].append({'encoded': url, 'decoded': dec})
        return det

    @staticmethod
    def _parse_wifi(data):
        det = {'raw': data, 'ssid': '', 'password': '', 'encryption': '', 'hidden': False}
        for key, field in [('T:', 'encryption'), ('S:', 'ssid'), ('P:', 'password'), ('H:', 'hidden')]:
            m = re.search(f'{key}([^;]*)', data)
            if m: det[field] = m.group(1) if field != 'hidden' else m.group(1).lower() == 'true'
        det['security_assessment'] = WIFI_SECURITY.get(det['encryption'].upper(), WIFI_SECURITY.get('nopass'))
        pwd = det['password']
        if pwd:
            det['password_analysis'] = {
                'length': len(pwd), 'has_upper': bool(re.search(r'[A-Z]', pwd)),
                'has_lower': bool(re.search(r'[a-z]', pwd)), 'has_digits': bool(re.search(r'[0-9]', pwd)),
                'has_special': bool(re.search(r'[^A-Za-z0-9]', pwd)),
                'entropy': PayloadAnalyzer._entropy(pwd),
                'is_common': pwd.lower() in {'password','12345678','123456789','qwerty123','password1'}}
        return det

    @staticmethod
    def _parse_vcard(data):
        fields = {}
        for line in data.split('\n'):
            line = line.strip()
            if ':' in line:
                k, _, v = line.partition(':')
                k = k.split(';')[0].upper()
                if k in ('FN','N','TEL','EMAIL','ORG','TITLE','ADR','URL','NOTE'):
                    if k in fields:
                        fields[k] = [fields[k], v] if not isinstance(fields[k], list) else fields[k] + [v]
                    else:
                        fields[k] = v
        return {'raw': data, 'fields': fields}

    @staticmethod
    def _parse_otp(data):
        p = urllib.parse.urlparse(data)
        params = dict(urllib.parse.parse_qs(p.query))
        return {'type': p.hostname, 'label': urllib.parse.unquote(p.path.lstrip('/')),
                'issuer': params.get('issuer',[''])[0], 'note': 'SENSITIVE — Contains 2FA secret key'}

    @staticmethod
    def _check_crypto(data):
        for cn in CRYPTO_PATTERNS:
            if data.lower().startswith(f'{cn}:'):
                addr = data.split(':')[1].split('?')[0]
                params = dict(urllib.parse.parse_qs(data.split('?',1)[1])) if '?' in data else {}
                return {'currency': cn, 'address': addr, 'params': params,
                        'amount': params.get('amount',[''])[0] if 'amount' in params else ''}
        for cn, pat in CRYPTO_PATTERNS.items():
            if re.match(pat, data.strip()): return {'currency': cn, 'address': data.strip(), 'params': {}}
        return None

    @staticmethod
    def _threats(data, pt, det):
        inds, iocs, score = [], [], 0
        dl = data.lower()

        ent = PayloadAnalyzer._entropy(data)
        if ent > 5.5:
            inds.append({'severity':'info','category':'encoding','description':f'High entropy ({ent:.2f}) — possible encoded/obfuscated payload'}); score += 5
        if any(ord(c)<32 and c not in '\n\r\t' for c in data):
            inds.append({'severity':'medium','category':'encoding','description':'Contains control characters'}); score += 15
        for pat in ['<script','javascript:','onerror=','onload=','eval(','document.cookie']:
            if pat in dl:
                inds.append({'severity':'high','category':'injection','description':f'Script injection: {pat}'}); score += 25
                iocs.append({'type':'injection_pattern','value':pat})

        if pt in ('url','url_no_schema'):
            dom = det.get('domain','')
            if det.get('is_ip_address'):
                inds.append({'severity':'high','category':'phishing','description':'URL uses raw IP address'}); score += 20
                iocs.append({'type':'suspicious_url','value':data})
            if det.get('is_shortened'):
                inds.append({'severity':'medium','category':'obfuscation','description':f'URL shortener ({dom}) — hides destination'}); score += 15
            if det.get('has_suspicious_tld'):
                inds.append({'severity':'medium','category':'phishing','description':'Suspicious/high-abuse TLD'}); score += 15
            if det.get('url_length',0) > 200:
                inds.append({'severity':'low','category':'obfuscation','description':f'Long URL ({det["url_length"]} chars)'}); score += 5
            if det.get('subdomain_count',0) > 3:
                inds.append({'severity':'medium','category':'phishing','description':f'Excessive subdomains ({det["subdomain_count"]})'}); score += 15
            kws = [k for k in PHISHING_KEYWORDS if k in dl]
            if kws:
                inds.append({'severity':'medium','category':'phishing','description':f'Phishing keywords: {", ".join(kws[:5])}'}); score += min(10*len(kws),25)
            for rp in det.get('redirect_params',[]):
                inds.append({'severity':'high','category':'redirect','description':f'Redirect param ({rp["param"]}) to another URL'}); score += 20
                iocs.append({'type':'redirect_target','value':rp['target']})
            if det.get('encoded_segments'):
                inds.append({'severity':'low','category':'obfuscation','description':'URL-encoded segments'}); score += 5
            if dom:
                try: dom.encode('ascii')
                except UnicodeEncodeError:
                    inds.append({'severity':'critical','category':'phishing','description':'IDN homograph attack — mixed scripts'}); score += 35
                    iocs.append({'type':'homograph_domain','value':dom})
            if dl.startswith('data:'):
                inds.append({'severity':'high','category':'injection','description':'Data URI — embedded executable'}); score += 25
            if det.get('port') and det['port'] not in (80,443):
                inds.append({'severity':'low','category':'suspicious','description':f'Non-standard port: {det["port"]}'}); score += 5
            iocs.append({'type':'url','value':data.strip()})
            if dom: iocs.append({'type':'domain','value':dom})

        elif pt == 'wifi':
            enc = det.get('encryption','').upper()
            if enc in ('WEP','') or enc == 'nopass':
                inds.append({'severity':'high','category':'security','description':f'Weak/no encryption ({enc or "OPEN"})'}); score += 25
            pa = det.get('password_analysis',{})
            if pa.get('is_common'):
                inds.append({'severity':'high','category':'security','description':'Common weak password'}); score += 20
            if pa.get('length',0) > 0 and pa['length'] < 8:
                inds.append({'severity':'medium','category':'security','description':f'Short password ({pa["length"]} chars)'}); score += 10
            if det.get('hidden'):
                inds.append({'severity':'info','category':'opsec','description':'Hidden SSID'})
            ssid = det.get('ssid','')
            if any(cs in ssid.lower() for cs in ['linksys','netgear','default','xfinity','att','tmobile','starbucks','airport','free']):
                inds.append({'severity':'medium','category':'security','description':f'Common SSID "{ssid}" — evil twin risk'}); score += 10

        elif pt == 'cryptocurrency':
            inds.append({'severity':'medium','category':'financial','description':f'Crypto payment ({det.get("currency","unknown")})'}); score += 10
            iocs.append({'type':'crypto_address','value':det.get('address','')})
            if det.get('amount'):
                inds.append({'severity':'info','category':'financial','description':f'Amount: {det["amount"]}'})

        elif pt == 'otp_auth':
            inds.append({'severity':'critical','category':'credential','description':'Contains 2FA/OTP secret — grants account access'}); score += 35
            iocs.append({'type':'otp_secret','value':'[REDACTED]'})

        elif pt == 'vcard':
            if 'URL' in det.get('fields',{}):
                inds.append({'severity':'low','category':'suspicious','description':'vCard contains URL'}); score += 5

        level = 'CRITICAL' if score >= 50 else 'HIGH' if score >= 30 else 'MEDIUM' if score >= 15 else 'LOW' if score > 0 else 'CLEAN'
        return {'indicators': inds, 'score': min(score, 100), 'level': level, 'iocs': iocs}


# ═══════════════════════════════════════════════════════════════════════════════
# IMAGE FORENSIC ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class ImageForensicAnalyzer:
    @staticmethod
    def analyze(image_path):
        result = {'file_info': {}, 'exif_data': {}, 'stego_indicators': {}, 'manipulation_indicators': [], 'hash_values': {}}

        st = os.stat(image_path)
        result['file_info'] = {'filename': os.path.basename(image_path), 'size_bytes': st.st_size,
            'size_human': ImageForensicAnalyzer._hs(st.st_size),
            'created': datetime.fromtimestamp(st.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(st.st_mtime).isoformat(),
            'extension': os.path.splitext(image_path)[1].lower()}

        with open(image_path, 'rb') as f:
            d = f.read()
            result['hash_values'] = {'md5': hashlib.md5(d).hexdigest(), 'sha1': hashlib.sha1(d).hexdigest(), 'sha256': hashlib.sha256(d).hexdigest()}

        try:
            img = Image.open(image_path)
            exif = img._getexif()
            if exif:
                for tid, val in exif.items():
                    tag = EXIF_TAGS.get(tid, str(tid))
                    try: result['exif_data'][tag] = str(val if not isinstance(val, bytes) else val.decode('utf-8', errors='replace'))[:200]
                    except: result['exif_data'][tag] = '[binary]'
            result['file_info'].update({'format': img.format, 'mode': img.mode, 'dimensions': f'{img.width}x{img.height}'})
        except: pass

        result['stego_indicators'] = ImageForensicAnalyzer._stego(image_path)
        result['manipulation_indicators'] = ImageForensicAnalyzer._manip(image_path)
        return result

    @staticmethod
    def _stego(path):
        ind = {'lsb_anomaly': False, 'chi_square_suspect': False, 'entropy_analysis': {}, 'overall_risk': 'LOW'}
        try:
            img = cv2.imread(path)
            if img is None: return ind
            if len(img.shape) == 3:
                for i, cn in enumerate(['Blue','Green','Red']):
                    lsb = img[:,:,i] & 1; r = np.mean(lsb)
                    ent = PayloadAnalyzer._entropy(''.join(map(str, lsb.flatten()[:10000])))
                    ind['entropy_analysis'][cn] = {'lsb_ones_ratio': round(float(r),4), 'lsb_entropy': round(ent,4), 'deviation': round(abs(r-0.5),4)}
                    if abs(r - 0.5) < 0.001: ind['lsb_anomaly'] = True
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if len(img.shape)==3 else img
            hist = cv2.calcHist([gray],[0],None,[256],[0,256]).flatten()
            chi, pairs = 0, 0
            for i in range(0,255,2):
                e = (hist[i]+hist[i+1])/2
                if e > 5: chi += ((hist[i]-e)**2)/e + ((hist[i+1]-e)**2)/e; pairs += 1
            if pairs > 0:
                nc = chi/pairs; ind['chi_square_value'] = round(float(nc),4)
                if nc < 0.5: ind['chi_square_suspect'] = True
            rs = (2 if ind['lsb_anomaly'] else 0) + (2 if ind['chi_square_suspect'] else 0)
            ind['overall_risk'] = 'HIGH' if rs >= 3 else 'MEDIUM' if rs >= 1 else 'LOW'
        except: pass
        return ind

    @staticmethod
    def _manip(path):
        inds = []
        try:
            img = cv2.imread(path)
            if img is None: return inds
            uc = len(np.unique(img.reshape(-1, img.shape[2] if len(img.shape)==3 else 1), axis=0))
            if uc / (img.shape[0]*img.shape[1]) < 0.01:
                inds.append({'type':'low_color_diversity','severity':'info','description':'Very few unique colors — may be generated/edited'})
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if len(img.shape)==3 else img
            if np.mean(cv2.Canny(gray,50,150) > 0) > 0.3:
                inds.append({'type':'high_edge_density','severity':'medium','description':'High edge density — possible overlay'})
        except: pass
        return inds

    @staticmethod
    def _hs(b):
        for u in ['B','KB','MB','GB']:
            if b < 1024: return f'{b:.1f} {u}'
            b /= 1024
        return f'{b:.1f} TB'


# ═══════════════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

def _esc(t):
    return t.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;').replace("'",'&#x27;')


class ReportGenerator:
    @staticmethod
    def generate(scan_results, output_path):
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        rid = hashlib.sha256(f'{ts}{id(scan_results)}'.encode()).hexdigest()[:12].upper()
        tot = len(scan_results)
        codes = sum(len(r.get('decode',{}).get('codes',[])) for r in scan_results)
        rc = Counter(r.get('payload_analysis',{}).get('risk_level','UNKNOWN') for r in scan_results)
        tiocs = sum(len(r.get('payload_analysis',{}).get('iocs',[])) for r in scan_results)

        css = """<style>
:root{--bg:#0a0e1a;--bg2:#1a2332;--bdr:#2a3a4a;--txt:#e2e8f0;--txt2:#94a3b8;--mut:#64748b;--acc:#3b82f6;--grn:#22c55e;--ylw:#f59e0b;--org:#f97316;--red:#ef4444;--cri:#dc2626;--pur:#a855f7;--cyn:#06b6d4;--mono:'Consolas',monospace;--sans:-apple-system,'Segoe UI',sans-serif}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:var(--sans);background:var(--bg);color:var(--txt);line-height:1.6}.ctr{max-width:1200px;margin:0 auto;padding:2rem}
.hdr{background:linear-gradient(135deg,#0f172a,#1e293b,#0f172a);border:1px solid var(--bdr);border-radius:16px;padding:2.5rem;margin-bottom:2rem;position:relative;overflow:hidden}
.hdr::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--acc),var(--pur),var(--cyn))}
.ht{display:flex;justify-content:space-between;align-items:flex-start}.brand{font-size:.85rem;font-weight:700;letter-spacing:3px;color:var(--acc);text-transform:uppercase}
h1{font-size:1.75rem;font-weight:700;margin:.5rem 0}.sub{color:var(--txt2);font-size:.95rem}.meta{text-align:right;font-size:.85rem;color:var(--mut);font-family:var(--mono)}.meta span{display:block;margin-bottom:.25rem}
.sb{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:2rem}.sc{background:var(--bg2);border:1px solid var(--bdr);border-radius:12px;padding:1.25rem;text-align:center}
.sv{font-size:2rem;font-weight:700;font-family:var(--mono);color:var(--acc)}.sl{font-size:.8rem;color:var(--mut);text-transform:uppercase;letter-spacing:1px;margin-top:.25rem}
.rb{display:inline-flex;padding:.35rem .85rem;border-radius:20px;font-size:.8rem;font-weight:700;text-transform:uppercase;font-family:var(--mono)}
.r-clean{background:rgba(34,197,94,.1);color:var(--grn);border:1px solid rgba(34,197,94,.3)}.r-low{background:rgba(245,158,11,.1);color:var(--ylw);border:1px solid rgba(245,158,11,.3)}
.r-medium{background:rgba(249,115,22,.1);color:var(--org);border:1px solid rgba(249,115,22,.3)}.r-high{background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.3)}
.r-critical{background:rgba(220,38,38,.15);color:var(--cri);border:1px solid rgba(220,38,38,.3)}
.sec{background:var(--bg2);border:1px solid var(--bdr);border-radius:12px;margin-bottom:1.5rem;overflow:hidden}.sh{padding:1.25rem 1.5rem;border-bottom:1px solid var(--bdr);font-weight:600;font-size:1.1rem}.sbd{padding:1.5rem}
table{width:100%;border-collapse:collapse}th{text-align:left;padding:.65rem 1rem;background:rgba(59,130,246,.05);color:var(--txt2);font-size:.8rem;text-transform:uppercase;border-bottom:1px solid var(--bdr)}
td{padding:.65rem 1rem;border-bottom:1px solid rgba(42,58,74,.5);font-size:.9rem;vertical-align:top}tr:last-child td{border-bottom:none}
.mono{font-family:var(--mono);font-size:.85rem;background:rgba(59,130,246,.08);padding:.15rem .5rem;border-radius:4px;word-break:break-all}
.pd{background:var(--bg);border:1px solid var(--bdr);border-radius:8px;padding:1rem;font-family:var(--mono);font-size:.85rem;word-break:break-all;white-space:pre-wrap;color:var(--cyn);max-height:200px;overflow-y:auto}
.ti{display:flex;gap:.75rem;padding:.75rem 0;border-bottom:1px solid rgba(42,58,74,.3)}.ti:last-child{border-bottom:none}
.ts{flex-shrink:0;width:70px;text-align:center;padding:.2rem .5rem;border-radius:4px;font-size:.7rem;font-weight:700;text-transform:uppercase;font-family:var(--mono)}
.s-cri{background:rgba(220,38,38,.15);color:var(--cri)}.s-hi{background:rgba(239,68,68,.1);color:var(--red)}.s-me{background:rgba(249,115,22,.1);color:var(--org)}.s-lo{background:rgba(245,158,11,.1);color:var(--ylw)}.s-in{background:rgba(6,182,212,.1);color:var(--cyn)}
.tc{font-size:.75rem;color:var(--mut);text-transform:uppercase}.td{font-size:.9rem;margin-top:.15rem}
.sm{display:flex;align-items:center;gap:1rem;padding:1rem}.st{flex:1;height:12px;background:var(--bg);border-radius:6px;overflow:hidden;border:1px solid var(--bdr)}.sf{height:100%;border-radius:6px}
.sn{font-family:var(--mono);font-size:1.5rem;font-weight:700;min-width:60px;text-align:right}
.qi{margin-bottom:2.5rem;padding-bottom:2.5rem;border-bottom:2px solid var(--bdr)}.qi:last-child{border-bottom:none}
.qh{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;padding:1rem 1.5rem;background:linear-gradient(135deg,rgba(59,130,246,.05),rgba(168,85,247,.05));border-radius:10px;border:1px solid var(--bdr)}
.qt{font-size:1.2rem;font-weight:600}.qtp{font-family:var(--mono);font-size:.85rem;color:var(--pur);background:rgba(168,85,247,.1);padding:.25rem .75rem;border-radius:6px}
.hg{display:grid;grid-template-columns:80px 1fr;gap:.5rem 1rem}.hl{font-size:.75rem;color:var(--mut);text-transform:uppercase;font-weight:600}.hv{font-family:var(--mono);font-size:.8rem;color:var(--txt2);word-break:break-all}
.ftr{text-align:center;padding:2rem;color:var(--mut);font-size:.8rem;border-top:1px solid var(--bdr);margin-top:2rem}
.cb{text-align:center;padding:.5rem;font-size:.75rem;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--mut);border-bottom:1px solid var(--bdr)}
</style>"""

        h = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>QR Forensic Report — {BRAND}</title>{css}</head><body>
<div class="cb">UNCLASSIFIED // FOR OFFICIAL USE ONLY // {BRAND} PROPRIETARY</div><div class="ctr">
<div class="hdr"><div class="ht"><div><div class="brand">{BRAND}</div><h1>QR Code Forensic Analysis Report</h1><div class="sub">Comprehensive payload analysis, threat assessment, and digital forensics</div></div>
<div class="meta"><span>Report ID: {rid}</span><span>Generated: {ts}</span><span>Engine: {TOOL_NAME} v{VERSION}</span></div></div></div>
<div class="sb"><div class="sc"><div class="sv">{tot}</div><div class="sl">Images Scanned</div></div>
<div class="sc"><div class="sv">{codes}</div><div class="sl">QR Codes Found</div></div>
<div class="sc"><div class="sv" style="color:var(--red)">{rc.get('CRITICAL',0)+rc.get('HIGH',0)}</div><div class="sl">High/Critical</div></div>
<div class="sc"><div class="sv" style="color:var(--cyn)">{tiocs}</div><div class="sl">IOCs Extracted</div></div></div>"""

        for i, r in enumerate(scan_results, 1):
            h += ReportGenerator._render(i, r)

        # IOC table
        all_iocs = [ioc for r in scan_results for ioc in r.get('payload_analysis',{}).get('iocs',[])]
        if all_iocs:
            h += '<div class="sec"><div class="sh">IOC Summary</div><div class="sbd"><table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>'
            seen = set()
            for ioc in all_iocs:
                k = f"{ioc['type']}:{ioc['value']}"
                if k not in seen:
                    seen.add(k)
                    h += f'<tr><td><span class="mono">{ioc["type"]}</span></td><td style="font-family:var(--mono);font-size:.8rem;color:var(--cyn);word-break:break-all">{_esc(ioc["value"])}</td></tr>'
            h += '</tbody></table></div></div>'

        h += f'<div class="ftr"><strong>{BRAND}</strong> — {TOOL_NAME} v{VERSION}<br>Report generated {ts} | ID: {rid}<br><em>Automated analysis — validate with qualified analyst.</em><br>&copy; {datetime.now().year} {BRAND} — All Rights Reserved</div></div></body></html>'

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(h)
        return output_path

    @staticmethod
    def _render(idx, r):
        dec = r.get('decode',{}); pa = r.get('payload_analysis',{}); st = r.get('structural',{}); imf = r.get('image_forensics',{})
        codes = dec.get('codes',[]); risk = pa.get('risk_level','UNKNOWN'); score = pa.get('threat_score',0)
        sc = '#22c55e' if score<15 else '#f59e0b' if score<30 else '#f97316' if score<50 else '#ef4444'
        fn = imf.get('file_info',{}).get('filename',f'Image {idx}'); pt = pa.get('payload_type','unknown').upper().replace('_',' ')

        h = f'<div class="qi"><div class="qh"><div><div class="qt">{_esc(fn)}</div><div style="font-size:.85rem;color:var(--mut);margin-top:.25rem">{len(codes)} QR code(s) | Engines: {", ".join(dec.get("engines_used",["none"]))}</div></div>'
        h += f'<div style="display:flex;gap:.75rem;align-items:center"><span class="qtp">{pt}</span><span class="rb r-{risk.lower()}">{risk}</span></div></div>'

        # Score
        h += f'<div class="sec"><div class="sh">Threat Score</div><div class="sbd"><div class="sm"><div class="st"><div class="sf" style="width:{score}%;background:{sc}"></div></div><div class="sn" style="color:{sc}">{score}/100</div></div></div></div>'

        # Payload
        if codes:
            raw = codes[0].get('data','')
            h += f'<div class="sec"><div class="sh">Decoded Payload</div><div class="sbd"><div class="pd">{_esc(raw)}</div>'
            h += f'<table style="margin-top:1rem"><tbody><tr><td style="width:180px;color:var(--mut)">Length</td><td>{pa.get("data_length",0)} chars</td></tr>'
            h += f'<tr><td style="color:var(--mut)">Entropy</td><td>{pa.get("entropy",0)}</td></tr><tr><td style="color:var(--mut)">Type</td><td><span class="mono">{pt}</span></td></tr>'
            det = pa.get('payload_details',{})
            if pa.get('payload_type')=='url':
                h += f'<tr><td style="color:var(--mut)">Domain</td><td class="mono">{_esc(det.get("domain",""))}</td></tr>'
                h += f'<tr><td style="color:var(--mut)">IP URL</td><td>{"Yes" if det.get("is_ip_address") else "No"}</td></tr>'
                h += f'<tr><td style="color:var(--mut)">Shortener</td><td>{"Yes" if det.get("is_shortened") else "No"}</td></tr>'
            elif pa.get('payload_type')=='wifi':
                h += f'<tr><td style="color:var(--mut)">SSID</td><td><strong>{_esc(det.get("ssid",""))}</strong></td></tr>'
                h += f'<tr><td style="color:var(--mut)">Encryption</td><td>{det.get("encryption","OPEN")}</td></tr>'
            elif pa.get('payload_type')=='cryptocurrency':
                h += f'<tr><td style="color:var(--mut)">Currency</td><td>{det.get("currency","").title()}</td></tr>'
                h += f'<tr><td style="color:var(--mut)">Address</td><td class="mono">{_esc(det.get("address",""))}</td></tr>'
            h += '</tbody></table></div></div>'

        # Threats
        inds = pa.get('threat_indicators',[])
        if inds:
            sev_cls = {'critical':'s-cri','high':'s-hi','medium':'s-me','low':'s-lo','info':'s-in'}
            h += '<div class="sec"><div class="sh">Threat Indicators</div><div class="sbd">'
            for ind in inds:
                sv = ind.get('severity','info')
                h += f'<div class="ti"><div class="ts {sev_cls.get(sv,"s-in")}">{sv}</div><div><div class="tc">{ind.get("category","")}</div><div class="td">{_esc(ind.get("description",""))}</div></div></div>'
            h += '</div></div>'

        if dec.get('multi_qr_detected'):
            h += '<div class="sec" style="border-color:var(--red)"><div class="sh" style="color:var(--red);background:rgba(239,68,68,.1)">MULTIPLE QR CODES — POSSIBLE OVERLAY ATTACK</div><div class="sbd"><p>Multiple QR codes detected. Common in QR poisoning attacks.</p></div></div>'

        # Structure
        if st:
            h += '<div class="sec"><div class="sh">QR Structure</div><div class="sbd"><table><tbody>'
            if st.get('estimated_version'): h += f'<tr><td style="color:var(--mut)">Version</td><td>{st["estimated_version"]}</td></tr>'
            ecc = st.get('estimated_ecc',{})
            if ecc: h += f'<tr><td style="color:var(--mut)">ECC</td><td>{ecc.get("name","?")} — {ecc.get("recovery","?")}</td></tr>'
            h += f'<tr><td style="color:var(--mut)">Finders</td><td>{len(st.get("finder_patterns",[]))} detected</td></tr>'
            h += f'<tr><td style="color:var(--mut)">Quiet Zone</td><td>{"Adequate" if st.get("quiet_zone_adequate") else "Insufficient"}</td></tr>'
            h += '</tbody></table></div></div>'

        # Image forensics
        if imf:
            fi = imf.get('file_info',{}); hs = imf.get('hash_values',{}); sg = imf.get('stego_indicators',{})
            h += f'<div class="sec"><div class="sh">Image Forensics</div><div class="sbd"><table><tbody>'
            h += f'<tr><td style="color:var(--mut)">Format</td><td>{fi.get("format","?")} ({fi.get("mode","")})</td></tr>'
            h += f'<tr><td style="color:var(--mut)">Dimensions</td><td>{fi.get("dimensions","?")}</td></tr>'
            h += f'<tr><td style="color:var(--mut)">Size</td><td>{fi.get("size_human","?")}</td></tr></tbody></table>'
            h += f'<div class="hg" style="margin-top:1rem"><div class="hl">MD5</div><div class="hv">{hs.get("md5","")}</div>'
            h += f'<div class="hl">SHA-1</div><div class="hv">{hs.get("sha1","")}</div>'
            h += f'<div class="hl">SHA-256</div><div class="hv">{hs.get("sha256","")}</div></div>'
            h += f'<p style="margin-top:1rem;color:var(--txt2);font-size:.85rem">Stego: <strong>{sg.get("overall_risk","LOW")}</strong> | LSB: {"Anomaly" if sg.get("lsb_anomaly") else "Normal"} | Chi²: {"Suspicious" if sg.get("chi_square_suspect") else "Normal"}</p>'
            h += '</div></div>'

        h += '</div>'
        return h


# ═══════════════════════════════════════════════════════════════════════════════
# DEMO GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class DemoGenerator:
    @staticmethod
    def generate_demo_set(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        demos = []
        payloads = [
            ("demo_url_clean.png", "https://www.example.com/about"),
            ("demo_url_suspicious.png", "https://secure-login.account-verify.tk/signin?redirect=https://evil.com/steal"),
            ("demo_url_shortener.png", "https://bit.ly/3xF4k3"),
            ("demo_wifi_wpa2.png", "WIFI:T:WPA2;S:CoffeeShop_Guest;P:Welcome2024!;H:false;;"),
            ("demo_wifi_open.png", "WIFI:T:nopass;S:FREE_AIRPORT_WIFI;;"),
            ("demo_vcard.png", "BEGIN:VCARD\nVERSION:3.0\nFN:Jane Smith\nORG:Acme Corp\nTEL:+1-555-0123\nEMAIL:jane@acme.com\nURL:https://acme.com\nEND:VCARD"),
            ("demo_crypto.png", "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.05"),
            ("demo_plain.png", "Hello, World! This is a simple text QR code."),
        ]
        for fn, data in payloads:
            path = os.path.join(output_dir, fn)
            try:
                enc = cv2.QRCodeEncoder.create()
                qr = enc.encode(data)
                if qr is not None:
                    qr = cv2.resize(qr, (400, 400), interpolation=cv2.INTER_NEAREST)
                    qr = cv2.copyMakeBorder(qr, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
                    cv2.imwrite(path, qr)
            except:
                img = Image.new('L', (480, 480), 255)
                d = ImageDraw.Draw(img)
                dh = hashlib.sha256(data.encode()).digest()
                ms, mc = 16, 25
                for r in range(mc):
                    for c in range(mc):
                        is_fp = False
                        for fr, fc_ in [(0,0),(0,mc-7),(mc-7,0)]:
                            if fr<=r<fr+7 and fc_<=c<fc_+7:
                                is_fp = True
                                fl = 0 if (r in (fr,fr+6) or c in (fc_,fc_+6) or (fr+2<=r<=fr+4 and fc_+2<=c<=fc_+4)) else 255
                        if not is_fp:
                            bi = (r*mc+c) % len(dh); bt = (r*mc+c) % 8
                            fl = 0 if (dh[bi]>>bt)&1 else 255
                        d.rectangle([40+c*ms, 40+r*ms, 40+c*ms+ms-1, 40+r*ms+ms-1], fill=fl)
                img.save(path)
            demos.append(path)
        return demos


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class QRForensicScanner:
    SUPPORTED = {'.png','.jpg','.jpeg','.bmp','.gif','.tiff','.tif','.webp'}

    def __init__(self):
        self.decoder = QRDecoder()

    def scan_file(self, path, log_cb=None):
        def log(m):
            if log_cb: log_cb(m)
            print(m)

        r = {'file': path, 'timestamp': datetime.now(timezone.utc).isoformat(),
             'decode': {}, 'payload_analysis': {}, 'structural': {}, 'image_forensics': {}}

        log(f"[*] Scanning: {os.path.basename(path)}")

        log("  [1/4] Decoding QR codes...")
        dec = self.decoder.decode_all(path); r['decode'] = dec
        codes = dec.get('codes', [])
        log(f"  [+] Found {len(codes)} code(s) via {', '.join(dec.get('engines_used',['none']))}")

        if not codes:
            log("  [!] No QR codes detected.")
            r['payload_analysis'] = {'payload_type':'none','risk_level':'N/A','threat_score':0,'threat_indicators':[],'iocs':[]}
        else:
            log(f"  [2/4] Analyzing payload ({len(codes[0]['data'])} chars)...")
            pa = PayloadAnalyzer.analyze(codes[0]['data']); r['payload_analysis'] = pa
            log(f"  [+] Type: {pa['payload_type']} | Risk: {pa['risk_level']} ({pa['threat_score']}/100)")

            log("  [3/4] Structural analysis...")
            sa = QRStructuralAnalyzer.analyze(path, dec); r['structural'] = sa
            ecc = sa.get('estimated_ecc',{})
            log(f"  [+] ECC: {ecc.get('name','Unknown')} | Finders: {len(sa.get('finder_patterns',[]))}")

        log("  [4/4] Image forensics...")
        imf = ImageForensicAnalyzer.analyze(path); r['image_forensics'] = imf
        sg = imf.get('stego_indicators',{})
        log(f"  [+] Stego: {sg.get('overall_risk','N/A')} | SHA-256: {imf.get('hash_values',{}).get('sha256','')[:16]}...")

        if codes:
            log(f"\n  RESULT: {pa['risk_level']} (Score: {pa['threat_score']}/100)")
            for ind in pa.get('threat_indicators',[])[:5]:
                log(f"    [{ind['severity'].upper()}] {ind['description']}")
            for ioc in pa.get('iocs',[])[:5]:
                log(f"    IOC {ioc['type']}: {ioc['value'][:80]}")
        log("")
        return r

    def scan_directory(self, dir_path, log_cb=None):
        files = sorted(f for f in Path(dir_path).rglob('*') if f.suffix.lower() in self.SUPPORTED)
        if log_cb: log_cb(f"[*] Found {len(files)} image(s) in {dir_path}\n")
        results = []
        for f in files:
            try: results.append(self.scan_file(str(f), log_cb))
            except Exception as e:
                if log_cb: log_cb(f"  [!] Error: {f}: {e}\n")
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# TKINTER GUI
# ═══════════════════════════════════════════════════════════════════════════════

def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext

    class App:
        def __init__(self, root):
            self.root = root
            self.root.title(f"{TOOL_NAME} v{VERSION} — {BRAND}")
            self.root.geometry("1280x900")
            self.root.minsize(1000, 700)
            self.root.configure(bg=COLORS['bg_dark'])
            self.scanner = QRForensicScanner()
            self.scan_results = []
            self._preview_photo = None
            self._setup_styles()
            self._build()

        def _setup_styles(self):
            s = ttk.Style(); s.theme_use('clam')
            s.configure('Dark.TFrame', background=COLORS['bg_dark'])
            s.configure('Card.TFrame', background=COLORS['bg_card'])
            s.configure('Mid.TFrame', background=COLORS['bg_mid'])
            for name, bg, fg, font in [
                ('Title.TLabel', COLORS['bg_dark'], COLORS['accent'], ('Helvetica',22,'bold')),
                ('Subtitle.TLabel', COLORS['bg_dark'], COLORS['text_secondary'], ('Helvetica',11)),
                ('Brand.TLabel', COLORS['bg_dark'], COLORS['accent'], ('Helvetica',10,'bold')),
                ('Dark.TLabel', COLORS['bg_dark'], COLORS['text'], ('Helvetica',10)),
                ('Card.TLabel', COLORS['bg_card'], COLORS['text'], ('Helvetica',10)),
                ('CardTitle.TLabel', COLORS['bg_card'], COLORS['text'], ('Helvetica',12,'bold')),
                ('CardMuted.TLabel', COLORS['bg_card'], COLORS['text_muted'], ('Helvetica',9)),
                ('Score.TLabel', COLORS['bg_card'], COLORS['accent'], ('Consolas',28,'bold')),
            ]:
                s.configure(name, background=bg, foreground=fg, font=font)

            s.configure('Accent.TButton', background=COLORS['accent'], foreground=COLORS['white'], font=('Helvetica',11,'bold'), padding=(20,12))
            s.map('Accent.TButton', background=[('active',COLORS['accent_hover'])])
            s.configure('Secondary.TButton', background=COLORS['bg_card'], foreground=COLORS['text'], font=('Helvetica',10), padding=(15,10))
            s.map('Secondary.TButton', background=[('active',COLORS['border'])])
            s.configure('Small.TButton', background=COLORS['bg_card'], foreground=COLORS['text_secondary'], font=('Helvetica',9), padding=(10,6))
            s.configure('dark.Horizontal.TProgressbar', background=COLORS['accent'], troughcolor=COLORS['bg_input'])

        def _build(self):
            main = ttk.Frame(self.root, style='Dark.TFrame')
            main.pack(fill=tk.BOTH, expand=True)

            # Header
            hdr = ttk.Frame(main, style='Dark.TFrame')
            hdr.pack(fill=tk.X, padx=30, pady=(20,10))

            accent = tk.Canvas(hdr, height=3, bg=COLORS['bg_dark'], highlightthickness=0)
            accent.pack(fill=tk.X, pady=(0,12))
            accent.update_idletasks()
            w = max(accent.winfo_width(), 800)
            accent.create_rectangle(0,0,w//3,3,fill=COLORS['accent'],outline='')
            accent.create_rectangle(w//3,0,2*w//3,3,fill=COLORS['purple'],outline='')
            accent.create_rectangle(2*w//3,0,w,3,fill=COLORS['cyan'],outline='')

            ht = ttk.Frame(hdr, style='Dark.TFrame'); ht.pack(fill=tk.X)
            lh = ttk.Frame(ht, style='Dark.TFrame'); lh.pack(side=tk.LEFT)
            ttk.Label(lh, text=BRAND, style='Brand.TLabel').pack(anchor='w')
            ttk.Label(lh, text="QR Code Forensic Scanner", style='Title.TLabel').pack(anchor='w')
            ttk.Label(lh, text="Advanced QR Analysis  •  Payload Forensics  •  Threat Detection", style='Subtitle.TLabel').pack(anchor='w', pady=(2,0))
            rh = ttk.Frame(ht, style='Dark.TFrame'); rh.pack(side=tk.RIGHT)
            ttk.Label(rh, text=f"v{VERSION}", style='Dark.TLabel').pack(anchor='e')

            # Toolbar
            tb = ttk.Frame(main, style='Dark.TFrame')
            tb.pack(fill=tk.X, padx=30, pady=(10,5))
            ttk.Button(tb, text="  Scan Image  ", style='Accent.TButton', command=self._scan_file).pack(side=tk.LEFT, padx=(0,8))
            ttk.Button(tb, text="  Scan Directory  ", style='Secondary.TButton', command=self._scan_dir).pack(side=tk.LEFT, padx=(0,8))
            ttk.Button(tb, text="  Generate Demos  ", style='Secondary.TButton', command=self._gen_demos).pack(side=tk.LEFT, padx=(0,8))
            ttk.Button(tb, text="  Export Report  ", style='Secondary.TButton', command=self._export_html).pack(side=tk.RIGHT, padx=(8,0))
            ttk.Button(tb, text="  Export JSON  ", style='Small.TButton', command=self._export_json).pack(side=tk.RIGHT, padx=(8,0))
            ttk.Button(tb, text="  Clear  ", style='Small.TButton', command=self._clear).pack(side=tk.RIGHT, padx=(8,0))

            # Content
            content = ttk.Frame(main, style='Dark.TFrame')
            content.pack(fill=tk.BOTH, expand=True, padx=30, pady=(10,20))

            # Left panel
            left = ttk.Frame(content, style='Dark.TFrame', width=360)
            left.pack(side=tk.LEFT, fill=tk.Y, padx=(0,15)); left.pack_propagate(False)

            # Preview
            pc = ttk.Frame(left, style='Card.TFrame'); pc.pack(fill=tk.X, pady=(0,10))
            ttk.Label(pc, text="IMAGE PREVIEW", style='CardMuted.TLabel').pack(anchor='w', padx=15, pady=(12,5))
            self.canvas = tk.Canvas(pc, width=330, height=280, bg=COLORS['bg_input'], highlightthickness=1, highlightbackground=COLORS['border'])
            self.canvas.pack(padx=15, pady=(0,15))
            self.canvas.create_text(165, 140, text="No image loaded", fill=COLORS['text_muted'], font=('Helvetica',11))

            # Results card
            rc = ttk.Frame(left, style='Card.TFrame'); rc.pack(fill=tk.X, pady=(0,10))
            ttk.Label(rc, text="SCAN RESULTS", style='CardMuted.TLabel').pack(anchor='w', padx=15, pady=(12,5))
            self.risk_lbl = ttk.Label(rc, text="—", style='Score.TLabel'); self.risk_lbl.pack(padx=15, pady=(5,2))
            self.risk_desc = ttk.Label(rc, text="Awaiting scan...", style='CardMuted.TLabel'); self.risk_desc.pack(padx=15, pady=(0,5))

            sf = ttk.Frame(rc, style='Card.TFrame'); sf.pack(fill=tk.X, padx=15, pady=(5,15))
            ttk.Label(sf, text="Threat Score", style='CardMuted.TLabel').pack(anchor='w')
            self.score_bar = ttk.Progressbar(sf, style='dark.Horizontal.TProgressbar', length=310, maximum=100, value=0)
            self.score_bar.pack(fill=tk.X, pady=(3,2))
            self.score_lbl = ttk.Label(sf, text="0 / 100", style='CardMuted.TLabel'); self.score_lbl.pack(anchor='e')

            # Info card
            ic = ttk.Frame(left, style='Card.TFrame'); ic.pack(fill=tk.X, pady=(0,10))
            ttk.Label(ic, text="PAYLOAD INFO", style='CardMuted.TLabel').pack(anchor='w', padx=15, pady=(12,5))
            self.type_lbl = ttk.Label(ic, text="Type: —", style='Card.TLabel'); self.type_lbl.pack(anchor='w', padx=15)
            self.eng_lbl = ttk.Label(ic, text="Engines: —", style='CardMuted.TLabel'); self.eng_lbl.pack(anchor='w', padx=15)
            self.stego_lbl = ttk.Label(ic, text="Stego Risk: —", style='CardMuted.TLabel'); self.stego_lbl.pack(anchor='w', padx=15, pady=(0,15))

            # Right panel — tabs
            right = ttk.Frame(content, style='Dark.TFrame')
            right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

            s = ttk.Style()
            s.configure('TNotebook', background=COLORS['bg_dark'], borderwidth=0)
            s.configure('TNotebook.Tab', background=COLORS['bg_card'], foreground=COLORS['text_secondary'], padding=(15,8), font=('Helvetica',10))
            s.map('TNotebook.Tab', background=[('selected',COLORS['accent'])], foreground=[('selected',COLORS['white'])])

            self.nb = ttk.Notebook(right)
            self.nb.pack(fill=tk.BOTH, expand=True)

            txt_opts = dict(wrap=tk.WORD, bg=COLORS['bg_input'], fg=COLORS['text'], insertbackground=COLORS['text'],
                            font=('Consolas',10), relief='flat', borderwidth=0, selectbackground=COLORS['accent'], padx=12, pady=12)

            tabs = {}
            for name, fg_color in [("Scan Log", COLORS['text']), ("Payload", COLORS['cyan']),
                                    ("Threats", COLORS['text']), ("IOCs", COLORS['cyan']), ("Forensics", COLORS['text'])]:
                f = ttk.Frame(self.nb, style='Card.TFrame')
                self.nb.add(f, text=f"  {name}  ")
                t = scrolledtext.ScrolledText(f, **{**txt_opts, 'fg': fg_color})
                t.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
                tabs[name] = t

            self.log_txt = tabs["Scan Log"]
            self.pay_txt = tabs["Payload"]
            self.thr_txt = tabs["Threats"]
            self.ioc_txt = tabs["IOCs"]
            self.for_txt = tabs["Forensics"]

            self.log_txt.insert(tk.END, f"  {BRAND} — {TOOL_NAME} v{VERSION}\n  Ready. Select an image to scan.\n\n")
            self.log_txt.config(state=tk.DISABLED)

            # Status bar
            sb = ttk.Frame(main, style='Mid.TFrame'); sb.pack(fill=tk.X, side=tk.BOTTOM)
            self.status = ttk.Label(sb, text=f"  {BRAND} — {TOOL_NAME} v{VERSION}  |  Ready",
                                     background=COLORS['bg_mid'], foreground=COLORS['text_muted'], font=('Helvetica',9))
            self.status.pack(side=tk.LEFT, padx=10, pady=5)

        def _log(self, msg):
            def _a():
                self.log_txt.config(state=tk.NORMAL)
                self.log_txt.insert(tk.END, msg + "\n")
                self.log_txt.see(tk.END)
                self.log_txt.config(state=tk.DISABLED)
            self.root.after(0, _a)

        def _set_status(self, t):
            self.root.after(0, lambda: self.status.configure(text=f"  {BRAND} — {TOOL_NAME} v{VERSION}  |  {t}"))

        def _load_preview(self, path):
            try:
                img = Image.open(path); img.thumbnail((330, 280), Image.Resampling.LANCZOS)
                self._preview_photo = ImageTk.PhotoImage(img)
                self.canvas.delete("all")
                self.canvas.create_image(165, 140, image=self._preview_photo, anchor=tk.CENTER)
            except: pass

        def _update(self, r):
            pa = r.get('payload_analysis',{}); dec = r.get('decode',{}); imf = r.get('image_forensics',{}); st = r.get('structural',{})
            risk = pa.get('risk_level','N/A'); score = pa.get('threat_score',0)
            rc = {'CLEAN':COLORS['green'],'LOW':COLORS['yellow'],'MEDIUM':COLORS['orange'],'HIGH':COLORS['red'],'CRITICAL':COLORS['critical']}
            self.risk_lbl.configure(text=risk, foreground=rc.get(risk, COLORS['text_muted']))
            self.risk_desc.configure(text=f"Threat Score: {score}/100")
            self.score_bar['value'] = score; self.score_lbl.configure(text=f"{score} / 100")

            pt = pa.get('payload_type','unknown').upper().replace('_',' ')
            self.type_lbl.configure(text=f"Type: {pt}")
            self.eng_lbl.configure(text=f"Engines: {', '.join(dec.get('engines_used',['none']))}")
            self.stego_lbl.configure(text=f"Stego Risk: {imf.get('stego_indicators',{}).get('overall_risk','N/A')}")

            # Payload tab
            self.pay_txt.delete('1.0', tk.END)
            codes = dec.get('codes',[])
            if codes:
                self.pay_txt.insert(tk.END, f"DECODED PAYLOAD ({pa.get('data_length',0)} chars)\n{'='*60}\n\n{codes[0].get('data','')}\n\n{'='*60}\n")
                self.pay_txt.insert(tk.END, f"Type:    {pt}\nEntropy: {pa.get('entropy',0)}\n")
                det = pa.get('payload_details',{})
                if pa.get('payload_type')=='url':
                    self.pay_txt.insert(tk.END, f"Domain:  {det.get('domain','')}\nScheme:  {det.get('scheme','')}\nSubs:    {det.get('subdomain_count',0)}\n")
                elif pa.get('payload_type')=='wifi':
                    self.pay_txt.insert(tk.END, f"SSID:    {det.get('ssid','')}\nEncrypt: {det.get('encryption','OPEN')}\n")
                elif pa.get('payload_type')=='cryptocurrency':
                    self.pay_txt.insert(tk.END, f"Coin:    {det.get('currency','')}\nAddr:    {det.get('address','')}\n")
                if len(codes) > 1:
                    self.pay_txt.insert(tk.END, f"\n{'!'*60}\nWARNING: {len(codes)} QR codes — possible overlay!\n")
            else:
                self.pay_txt.insert(tk.END, "No QR codes detected.\n")

            # Threats tab
            self.thr_txt.delete('1.0', tk.END)
            inds = pa.get('threat_indicators',[])
            if inds:
                self.thr_txt.insert(tk.END, f"THREAT INDICATORS ({len(inds)})\n{'='*60}\n\n")
                for i in inds:
                    self.thr_txt.insert(tk.END, f"  [{i['severity'].upper():8s}] [{i.get('category','')}]\n  {i['description']}\n\n")
            else:
                self.thr_txt.insert(tk.END, "No threats found — payload appears clean.\n")

            # IOCs tab
            self.ioc_txt.delete('1.0', tk.END)
            iocs = pa.get('iocs',[])
            if iocs:
                self.ioc_txt.insert(tk.END, f"INDICATORS OF COMPROMISE ({len(iocs)})\n{'='*60}\n\n")
                for ioc in iocs:
                    self.ioc_txt.insert(tk.END, f"  [{ioc['type']:20s}]  {ioc['value']}\n")
            else:
                self.ioc_txt.insert(tk.END, "No IOCs extracted.\n")

            # Forensics tab
            self.for_txt.delete('1.0', tk.END)
            fi = imf.get('file_info',{}); hs = imf.get('hash_values',{}); sg = imf.get('stego_indicators',{})
            self.for_txt.insert(tk.END, f"FILE INFO\n{'='*60}\n")
            self.for_txt.insert(tk.END, f"  File:       {fi.get('filename','')}\n  Format:     {fi.get('format','?')} ({fi.get('mode','')})\n")
            self.for_txt.insert(tk.END, f"  Dimensions: {fi.get('dimensions','?')}\n  Size:       {fi.get('size_human','?')}\n")
            self.for_txt.insert(tk.END, f"\nHASHES\n{'='*60}\n")
            self.for_txt.insert(tk.END, f"  MD5:     {hs.get('md5','')}\n  SHA-1:   {hs.get('sha1','')}\n  SHA-256: {hs.get('sha256','')}\n")
            self.for_txt.insert(tk.END, f"\nSTEGO ANALYSIS\n{'='*60}\n")
            self.for_txt.insert(tk.END, f"  Risk:       {sg.get('overall_risk','N/A')}\n  LSB:        {'ANOMALY' if sg.get('lsb_anomaly') else 'Normal'}\n")
            self.for_txt.insert(tk.END, f"  Chi-Square: {'SUSPICIOUS' if sg.get('chi_square_suspect') else 'Normal'}")
            if 'chi_square_value' in sg: self.for_txt.insert(tk.END, f" ({sg['chi_square_value']})")
            self.for_txt.insert(tk.END, "\n")
            for cn, cd in sg.get('entropy_analysis',{}).items():
                self.for_txt.insert(tk.END, f"  {cn:5s} LSB:  ones={cd.get('lsb_ones_ratio','')} ent={cd.get('lsb_entropy','')} dev={cd.get('deviation','')}\n")
            if st:
                self.for_txt.insert(tk.END, f"\nQR STRUCTURE\n{'='*60}\n")
                if st.get('estimated_version'): self.for_txt.insert(tk.END, f"  Version:    {st['estimated_version']}\n")
                ecc = st.get('estimated_ecc',{})
                if ecc: self.for_txt.insert(tk.END, f"  ECC:        {ecc.get('name','?')} ({ecc.get('recovery','?')})\n")
                self.for_txt.insert(tk.END, f"  Finders:    {len(st.get('finder_patterns',[]))}\n  Quiet Zone: {'OK' if st.get('quiet_zone_adequate') else 'Insufficient'}\n")
            exif = imf.get('exif_data',{})
            if exif:
                self.for_txt.insert(tk.END, f"\nEXIF METADATA\n{'='*60}\n")
                for k, v in list(exif.items())[:20]:
                    self.for_txt.insert(tk.END, f"  {k:20s}: {v}\n")

        def _scan_file(self):
            path = filedialog.askopenfilename(title="Select QR Code Image",
                filetypes=[("Images","*.png *.jpg *.jpeg *.bmp *.gif *.tiff *.tif *.webp"),("All","*.*")])
            if not path: return
            self._load_preview(path); self._set_status("Scanning..."); self.nb.select(0)
            def _go():
                r = self.scanner.scan_file(path, log_cb=self._log)
                self.scan_results = [r]
                self.root.after(0, lambda: self._update(r))
                self._set_status(f"Done — {r.get('payload_analysis',{}).get('risk_level','?')}")
            threading.Thread(target=_go, daemon=True).start()

        def _scan_dir(self):
            d = filedialog.askdirectory(title="Select Directory")
            if not d: return
            self._set_status("Batch scanning..."); self.nb.select(0)
            def _go():
                rs = self.scanner.scan_directory(d, log_cb=self._log)
                self.scan_results = rs
                if rs:
                    self.root.after(0, lambda: self._update(rs[-1]))
                    self.root.after(0, lambda: self._load_preview(rs[-1].get('file','')))
                self._set_status(f"Batch done — {len(rs)} images")
            threading.Thread(target=_go, daemon=True).start()

        def _gen_demos(self):
            d = filedialog.askdirectory(title="Output Directory for Demos")
            if not d: return
            self._log("[*] Generating demo QR codes...")
            demos = DemoGenerator.generate_demo_set(d)
            self._log(f"[+] Generated {len(demos)} demos\n[*] Scanning...\n")
            self._set_status("Scanning demos...")
            def _go():
                rs = self.scanner.scan_directory(d, log_cb=self._log)
                self.scan_results = rs
                if rs: self.root.after(0, lambda: self._update(rs[-1]))
                self._set_status(f"Demo done — {len(rs)} images")
            threading.Thread(target=_go, daemon=True).start()

        def _export_html(self):
            if not self.scan_results:
                messagebox.showwarning("No Results", "Run a scan first."); return
            p = filedialog.asksaveasfilename(title="Save Report", defaultextension=".html",
                filetypes=[("HTML","*.html")], initialfile=f"qr_forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
            if not p: return
            ReportGenerator.generate(self.scan_results, p)
            self._log(f"[+] Report: {p}"); messagebox.showinfo("Exported", f"Report saved:\n{p}")

        def _export_json(self):
            if not self.scan_results:
                messagebox.showwarning("No Results", "Run a scan first."); return
            p = filedialog.asksaveasfilename(title="Save JSON", defaultextension=".json",
                filetypes=[("JSON","*.json")], initialfile=f"qr_forensic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            if not p: return
            def clean(o):
                if isinstance(o,dict): return {k:clean(v) for k,v in o.items()}
                if isinstance(o,list): return [clean(i) for i in o]
                if isinstance(o,(np.integer,)): return int(o)
                if isinstance(o,(np.floating,)): return float(o)
                if isinstance(o,np.ndarray): return o.tolist()
                return o
            with open(p,'w') as f: json.dump(clean(self.scan_results), f, indent=2)
            self._log(f"[+] JSON: {p}")

        def _clear(self):
            self.scan_results = []; self._preview_photo = None
            self.canvas.delete("all")
            self.canvas.create_text(165, 140, text="No image loaded", fill=COLORS['text_muted'], font=('Helvetica',11))
            self.risk_lbl.configure(text="—", foreground=COLORS['accent'])
            self.risk_desc.configure(text="Awaiting scan...")
            self.score_bar['value'] = 0; self.score_lbl.configure(text="0 / 100")
            self.type_lbl.configure(text="Type: —"); self.eng_lbl.configure(text="Engines: —"); self.stego_lbl.configure(text="Stego Risk: —")
            for w in [self.pay_txt, self.thr_txt, self.ioc_txt, self.for_txt]: w.delete('1.0', tk.END)
            self.log_txt.config(state=tk.NORMAL); self.log_txt.delete('1.0', tk.END)
            self.log_txt.insert(tk.END, f"  {BRAND} — {TOOL_NAME} v{VERSION}\n  Cleared.\n\n")
            self.log_txt.config(state=tk.DISABLED); self._set_status("Ready")

    from PIL import ImageTk
    root = tk.Tk(); App(root); root.mainloop()


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                      QR CODE FORENSIC SCANNER v{VERSION}                        ║
║                              {BRAND} ™                                       ║
║        Advanced QR Code Analysis • Payload Forensics • Threat Detection    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

    if len(sys.argv) == 1:
        print(banner); print("[*] Launching GUI...\n"); launch_gui(); return

    print(banner)
    parser = argparse.ArgumentParser(description=f'{TOOL_NAME} — {BRAND}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"  Run with no arguments to launch GUI.\n\n  {BRAND} — All Rights Reserved")
    parser.add_argument('target', nargs='?', help='Image file or directory')
    parser.add_argument('--report', '-r', help='HTML report output path')
    parser.add_argument('--json', '-j', action='store_true', help='JSON output')
    parser.add_argument('--demo', '-d', action='store_true', help='Generate & scan demo QRs')
    parser.add_argument('--no-report', action='store_true', help='Skip HTML report')
    parser.add_argument('--output-dir', '-o', default='.', help='Output directory')
    parser.add_argument('--gui', '-g', action='store_true', help='Force GUI')
    args = parser.parse_args()

    if args.gui: launch_gui(); return

    scanner = QRForensicScanner()
    if args.demo:
        print("[*] Generating demos...")
        dd = os.path.join(args.output_dir, 'demo_qr_codes')
        DemoGenerator.generate_demo_set(dd)
        print(f"[+] Demos in {dd}/\n[*] Scanning...\n")
        results = scanner.scan_directory(dd)
    elif args.target:
        if os.path.isdir(args.target): results = scanner.scan_directory(args.target)
        elif os.path.isfile(args.target): results = [scanner.scan_file(args.target)]
        else: print(f"[!] Not found: {args.target}"); sys.exit(1)
    else: parser.print_help(); sys.exit(0)

    if args.json:
        def clean(o):
            if isinstance(o,dict): return {k:clean(v) for k,v in o.items()}
            if isinstance(o,list): return [clean(i) for i in o]
            if isinstance(o,(np.integer,)): return int(o)
            if isinstance(o,(np.floating,)): return float(o)
            if isinstance(o,np.ndarray): return o.tolist()
            return o
        print("\n" + json.dumps(clean(results), indent=2))

    if not args.no_report and results:
        rp = args.report or os.path.join(args.output_dir, f'qr_forensic_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html')
        ReportGenerator.generate(results, rp); print(f"\n[+] Report: {rp}")

    print(f"\n{'='*70}\n  SCAN COMPLETE — {len(results)} image(s)")
    tc = sum(len(r.get('decode',{}).get('codes',[])) for r in results)
    print(f"  {tc} QR code(s) decoded")
    rcs = Counter(r.get('payload_analysis',{}).get('risk_level','N/A') for r in results)
    for l in ['CRITICAL','HIGH','MEDIUM','LOW','CLEAN','N/A']:
        if rcs.get(l,0): print(f"  {l}: {rcs[l]}")
    print(f"{'='*70}\n")

if __name__ == '__main__':
    main()
