# Copyright (c) RedTiger by Loxy0devlp
# Licensed under the MIT License.
# See LICENSE file in the project root for full license text.

from Config.Utils import *

port_https = next((p for p, name in data_ports.items() if name == "HTTPS"), None)

def IpStatus(ip):
    try:
        ipaddress.ip_address(ip)
        if ip in blacklists: status = False
        else: status = True
    except: status = False
    return status

def DomainStatus(domain):
    status = False
    try:
        if domain is None: return False
        if ":" in domain: domain = domain.rsplit(":", 1)[0]
        if domain == "localhost": return True
        if IpStatus(domain): return True
        domain_regex = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
        if not domain_regex.match(domain): return False
        try:
            socket.gethostbyname(domain)
            status = True
        except: status = False
    except: status = False
    return status

def UrlStatus(url, session, http_timeout):
    latency = None
    try:
        start = time.time()
        response = session.get(url, allow_redirects=True, timeout=http_timeout)
        latency = round((time.time() - start) * 1000, 2)
        status = str(response.status_code)
    except: response, status = None, "404"
    return response, status, latency

def TargetGetUrlAndStatusAndLatency(target, session, http_timeout, log=True):
    url = response = status_url = latency = None
    json_format = None
    try:
        if not target.lower().startswith(("http://", "https://")):
            url_https = f"https://{target}"
            url_http  = f"http://{target}"
            response, status_url, latency = UrlStatus(url_https, session, http_timeout)
            if status_url.startswith(("4", "5")):
                response, status_url, latency = UrlStatus(url_http, session, http_timeout)
                if not status_url.startswith(("4", "5")):
                    url = url_http
            else: url = url_https
        else: 
            url = target
            response, status_url, latency = UrlStatus(target, session, http_timeout)

        if url and log and not status_url.startswith(("4", "5")):
            Add(f"URL: {white + str(url)}")
            Add(f"URL status code: {white + str(status_url)}")
            Add(f"URL latency: {white + str(latency)}ms")
            json_format = json.dumps({"URL": url, "URL status code": status_url, "URL latency": str(latency) + "ms"})
    except: pass
    return url, response, status_url, latency, json_format

def TargetGetDomain(url, log=True):
    domain = None
    json_format = None
    try: 
        domain = urllib.parse.urlparse(url).netloc
        domain = re.sub(r":\d+$", "", domain)
        if not DomainStatus(domain): domain = None
        if log and domain: Add(f"Domain: {white}{domain}")
    except: pass
    if domain: json_format = json.dumps({"Domain": domain})
    return domain, json_format

def TargetGetIp(domain, detect_target, log=True):
    ip = None
    port = None
    json_format = None
    try:
        if detect_target in ("localhost:port", "ip:port"):
            if domain.startswith("[") and "]:" in domain:
                domain, port_part = domain[1:].split("]:")
                port = int(port_part)
            elif ":" in domain:
                domain, port_part = domain.split(":", 1)
                port = int(port_part)
        try: ip = socket.gethostbyname(domain)
        except: pass
        if IpStatus(domain): ip = domain
        if not IpStatus(ip): ip = None
        else: 
            if log: Add(f"IP: {white}{ip}")
    except: pass
    if ip and port: json_format = json.dumps({"IP": ip, "Port": port})
    elif ip: json_format = json.dumps({"IP": ip})
    return ip, port, json_format

def UrlSecureConnection(url, log=True):
    status = None
    json_format = None
    status = url.startswith("https://")
    if log: Add(f"URL secure connection: {white}{status}")
    if status: json_format = json.dumps({"URL secure connection": status})
    return status, json_format

def UrlCheckRedirects(response, log=True):
    json_format = None
    redirects = []
    try:
        redirects = [resp.url for resp in response.history] + [response.url]
        if log: Add(f"Redirect: {white}{' -> '.join(redirects)}")
        json_format = json.dumps({"Redirects": redirects})
    except: pass
    return redirects, json_format

def UrlDetectInlineScripts(response, log=True):
    json_format = None
    scripts_count = 0
    suspicious = []
    suspicious_patterns = [
        "eval(", "document.write(", "document.writeln(", "innerHTML", "outerHTML",
        "setTimeout(", "setInterval(", "Function(", "onload=", "onerror=",
        "onclick=", "onmouseover=", "appendChild(", "insertAdjacentHTML(",
        "XMLHttpRequest(", "fetch(", "eval.call(", "eval.apply("
    ]

    try:
        if not response: return {"Inline scripts": 0, "Suspicious patterns": []}, json_format
        soup = bs4.BeautifulSoup(response.text, "html.parser")
        for script in soup.find_all("script"):
            if not script.get("src"):
                scripts_count += 1
                content = script.string or ""
                for pattern in suspicious_patterns:
                    if pattern in content:
                        suspicious.append(pattern)
        if log:
            Add(f"Inline scripts found: {white}{scripts_count}")
            Add(f"Suspicious patterns: {white}{' / '.join(set(suspicious)) if suspicious else 'None'}")
        result = {"Inline scripts": scripts_count, "Suspicious patterns": list(set(suspicious))}
        json_format = json.dumps({"Inline scripts": scripts_count, "Suspicious patterns": list(set(suspicious))})
    except: pass
    return result, json_format

def UrlCheckFormsSecurity(response, url, log=True):
    json_format = None
    forms_info = {"Forms checked": 0, "Insecure forms": 0}
    if not response: return forms_info, json_format
    soup = bs4.BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    forms_info["Forms checked"] = len(forms)
    for f in forms:
        action = f.get("action", url)
        method = f.get("method", "get").lower()
        if method == "post" and not action.startswith("https://"):
            forms_info["Insecure forms"] += 1
    if log:
        Add(f"Forms checked: {white}{forms_info['Forms checked']}")
        Add(f"Insecure forms: {white}{forms_info['Insecure forms']}")
    json_format = json.dumps(forms_info)
    return forms_info, json_format

def UrlDetectApi(response, log=True):
    json_format = None
    apis = []
    if not response: return apis, json_format
    soup = bs4.BeautifulSoup(response.text, "html.parser")
    for s in soup.find_all("script", src=True):
        if "/api/" in s["src"].lower():
            apis.append(s["src"])
    for link in soup.find_all("a", href=True):
        if "/api/" in link["href"].lower():
            apis.append(link["href"])
    if apis:
        if log: Add(f"API detected: {white}{' / '.join(apis)}")
        json_format = json.dumps({"API": apis})
    return apis, json_format

def DomainReserved(domain, log=True):
    status = None
    json_format = None
    try:
        if not domain: return status, json_format
        reserved = (".local", ".internal", ".test", ".example", ".invalid", ".onion")
        status = domain.lower().endswith(reserved)
        if log: Add(f"Domain reserved: {white}{status}")
        json_format = json.dumps({"Domain reserved": status})
    except: pass
    return status, json_format

def _ssl_scan_context(proto=None):
    if proto is None:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(proto)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def TargetSslCertificateInfo(domain, socket_timeout, log=True):
    cn = issuer = issuer_org = not_before = not_after = expired = not_yet_valid = None
    san = []
    json_format = None

    try:
        ctx = _ssl_scan_context()

        with socket.create_connection((domain, port_https), timeout=socket_timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                subject = dict(cert.get_subject().get_components())
                issuer_d = dict(cert.get_issuer().get_components())
                cn = subject.get(b"CN", b"").decode()
                issuer = issuer_d.get(b"CN", b"").decode()
                issuer_org = issuer_d.get(b"O", b"").decode()
                not_before_dt = datetime.datetime.strptime(cert.get_notBefore().decode(), "%Y%m%d%H%M%SZ")
                not_after_dt = datetime.datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
                not_before = not_before_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                not_after  = not_after_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                now = datetime.datetime.utcnow()
                expired = now > not_after_dt
                not_yet_valid = now < not_before_dt

                for i in range(cert.get_extension_count()):
                    ext = cert.get_extension(i)
                    if ext.get_short_name() == b"subjectAltName":
                        san = str(ext).replace("DNS:", "").split(", ")

        if log:
            Add(f"SSL cn: {white}{cn}")
            Add(f"SSL issuer: {white}{issuer_org} ({issuer})")
            Add(f"SSL san: {white}{' / '.join(san)}")
            Add(f"SSL valid from: {white}{not_before}")
            Add(f"SSL valid until: {white}{not_after}")
            Add(f"SSL expired: {white}{expired}")
            Add(f"SSL not yet valid: {white}{not_yet_valid}")

        json_format = json.dumps({"SSL cn": cn, "SSL issuer": issuer, "SSL issuer org": issuer_org, "SSL san": san, "SSL valid from": not_before, "SSL valid until": not_after, "SSL expired": expired, "SSL not yet valid": not_yet_valid})

    except: pass
    return cn, issuer, issuer_org, san, not_before, not_after, expired, not_yet_valid, json_format

def TargetSslKeyInfo(domain, socket_timeout, log=True):
    key_type    = key_bits = sig_algo = weak_key = None
    json_format = None

    try:
        ctx = _ssl_scan_context()
        with socket.create_connection((domain, port_https), timeout=socket_timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                key = cert.get_pubkey()
                key_bits = key.bits()
                if key.type() == OpenSSL.crypto.TYPE_RSA:
                    key_type = "RSA"
                    weak_key = key_bits < 2048
                elif key.type() == OpenSSL.crypto.TYPE_EC:
                    key_type = "ECDSA"
                    weak_key = key_bits < 256
                elif key.type() == OpenSSL.crypto.TYPE_DSA:
                    key_type = "DSA"
                    weak_key = True
                else:
                    key_type = "Unknown"
                    weak_key = True
                sig_algo = cert.get_signature_algorithm().decode()

        if log:
            Add(f"SSL public key type: {white}{key_type}")
            Add(f"SSL public key bits: {white}{key_bits}")
            Add(f"SSL signature algorithm: {white}{sig_algo}")
            Add(f"SSL weak key: {white}{weak_key}")

        json_format = json.dumps({"SSL public key type": key_type, "SSL public key bits": key_bits, "SSL signature algorithm": sig_algo, "SSL weak key": weak_key})

    except: pass
    return key_type, key_bits, sig_algo, weak_key, json_format

def TargetSslCipherInfo(domain, socket_timeout, log=True):
    tls_version = cipher_suite = cipher_bits = forward_secrecy = weak_cipher = None
    json_format = None

    try:
        ctx = _ssl_scan_context()

        with socket.create_connection((domain, port_https), timeout=socket_timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ssock:
                cipher = ssock.cipher() 
                cipher_suite = cipher[0]
                tls_version = ssock.version()
                cipher_bits = cipher[2]
                if tls_version == "TLSv1.3": forward_secrecy = True
                else: forward_secrecy = "ECDHE" in cipher_suite or "DHE" in cipher_suite
                weak_ciphers_list = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")
                weak_cipher = any(w in cipher_suite for w in weak_ciphers_list)

        if log:
            Add(f"SSL negotiated TLS: {white}{tls_version}")
            Add(f"SSL cipher suite: {white}{cipher_suite}")
            Add(f"SSL cipher bits: {white}{cipher_bits}")
            Add(f"SSL forward secrecy: {white}{forward_secrecy}")
            Add(f"SSL weak cipher: {white}{weak_cipher}")

        json_format = json.dumps({"SSL negotiated TLS": tls_version, "SSL cipher suite": cipher_suite, "SSL cipher bits": cipher_bits, "SSL forward secrecy": forward_secrecy, "SSL weak cipher": weak_cipher})
    except: pass
    return tls_version, cipher_suite, cipher_bits, forward_secrecy, weak_cipher, json_format

def TargetSslTlsSupport(domain, socket_timeout, log=True):
    sslv3 = tlsv1_0 = tlsv1_1 = tlsv1_2 = tlsv1_3 = None
    json_format = None

    protocols = {
        "SSLv3": getattr(ssl, "PROTOCOL_SSLv3", None),
        "TLSv1.0": ssl.PROTOCOL_TLSv1,
        "TLSv1.1": ssl.PROTOCOL_TLSv1_1,
        "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
        "TLSv1.3": ssl.PROTOCOL_TLS,
    }

    results = {}

    try:
        for name, proto in protocols.items():
            if not proto:
                results[name] = False
                continue
            try:
                ctx = _ssl_scan_context(proto)
                with socket.create_connection((domain, port_https), timeout=socket_timeout) as s:
                    with ctx.wrap_socket(s, server_hostname=domain):
                        results[name] = True
            except: results[name] = False

        sslv3   = results.get("SSLv3")
        tlsv1_0 = results.get("TLSv1.0")
        tlsv1_1 = results.get("TLSv1.1")
        tlsv1_2 = results.get("TLSv1.2")
        tlsv1_3 = results.get("TLSv1.3")

        ssl_dict = {
            "SSL SSLv3 supported": sslv3,
            "SSL TLSv1.0 supported": tlsv1_0,
            "SSL TLSv1.1 supported": tlsv1_1,
            "SSL TLSv1.2 supported": tlsv1_2,
            "SSL TLSv1.3 supported": tlsv1_3
        }

        ssl_dict_filtered = {k: v for k, v in ssl_dict.items() if v}

        if log:
            for k, v in ssl_dict_filtered.items():
                Add(f"{k}: {white}{v}")

        json_format = json.dumps(ssl_dict_filtered)

    except:pass
    return sslv3, tlsv1_0, tlsv1_1, tlsv1_2, tlsv1_3, json_format

def TargetSslOcspStapling(domain, socket_timeout, log=True):
    ocsp_enabled = False
    json_format = None

    try:
        ctx = _ssl_scan_context()
        with socket.create_connection((domain, port_https), timeout=socket_timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                for i in range(cert.get_extension_count()):
                    ext = cert.get_extension(i)
                    if b"OCSP" in ext.get_short_name():
                        ocsp_enabled = True
                        break

        if log: Add(f"SSL OCSP stapling: {white}{ocsp_enabled}")
        json_format = json.dumps({"SSL OCSP stapling": ocsp_enabled})

    except: pass
    return ocsp_enabled, json_format

def TargetSslCertRevocation(domain, socket_timeout, log=True):
    revocation_status = {}
    json_format = None
    try:
        ctx = _ssl_scan_context()
        with socket.create_connection((domain, port_https), timeout=socket_timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                for i in range(cert.get_extension_count()):
                    ext = cert.get_extension(i)
                    name = ext.get_short_name().decode()
                    value = str(ext).replace("\n", " ").replace("  ", " ").strip()
                    if name == "crlDistributionPoints":
                        m = re.search(r"URI:([^\s]+)", value)
                        if m: revocation_status["CRL"] = m.group(1)
                    elif name == "authorityInfoAccess":
                        m = re.search(r"URI:([^\s]+)", value)
                        if m: revocation_status["OCSP"] = m.group(1)
        if log:
            if "CRL" in revocation_status: Add(f"SSL cert revocation CRL: {white}{revocation_status['CRL']}")
            if "OCSP" in revocation_status: Add(f"SSL cert revocation OCSP: {white}{revocation_status['OCSP']}")
        if revocation_status:
            json_format = json.dumps({"SSL cert revocation": revocation_status})
    except: pass
    return revocation_status, json_format

def TargetSslKeyReuse(domain, socket_timeout, known_keys=None, log=True):
    reused = False
    json_format = None
    if known_keys is None: known_keys = {}
    try:
        ctx = _ssl_scan_context()
        with socket.create_connection((domain, port_https), timeout=socket_timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                pubkey = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey()).decode()
                if pubkey in known_keys.values(): reused = True
                known_keys[domain] = pubkey
        if log: Add(f"SSL key reused: {white}{reused}")
        json_format = json.dumps({"SSL key reuse": reused})
    except: pass
    return reused, json_format, known_keys

def TargetSslRenegotiation(domain, socket_timeout, log=True):
    renegotiation_supported = None
    json_format = None
    try:
        ctx = _ssl_scan_context()
        with socket.create_connection((domain, port_https), timeout=socket_timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ssock: renegotiation_supported = None
        if log and renegotiation_supported is not None: Add(f"SSL renegotiation supported: {white}{renegotiation_supported}")
        if renegotiation_supported is not None: json_format = json.dumps({"SSL renegotiation": renegotiation_supported})
    except: pass
    return renegotiation_supported, json_format

def TargetSslCompression(domain, socket_timeout, log=True):
    compression = None
    json_format = None
    try:
        ctx = _ssl_scan_context()
        ctx.options |= ssl.OP_NO_COMPRESSION
        with socket.create_connection((domain, port_https), timeout=socket_timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain):
                compression = False
        if log and compression is not None:
            Add(f"SSL compression enabled: {white}{compression}")
        if compression is not None:
            json_format = json.dumps({"SSL compression enabled": compression})
    except: pass
    return compression, json_format

def TargetSslSessionResumption(domain, socket_timeout, log=True):
    resumption = None
    json_format = None
    try:
        ctx = _ssl_scan_context()

        with socket.create_connection((domain, port_https), timeout=socket_timeout) as s1:
            with ctx.wrap_socket(s1, server_hostname=domain) as ssock1:
                session = ssock1.session

        with socket.create_connection((domain, port_https), timeout=socket_timeout) as s2:
            with ctx.wrap_socket(s2, server_hostname=domain, session=session) as ssock2:
                resumption = ssock2.session_reused

        if log and resumption is not None:
            Add(f"SSL session resumption: {white}{resumption}")
        if resumption is not None:
            json_format = json.dumps({"SSL session resumption": resumption})
    except: pass
    return resumption, json_format

def TargetGetHttpHeaders(response, log=True):
    headers_dict = {}
    json_format = None
    try:
        if not response: return headers_dict, json_format
        max_len = max(len(h) for h in response.headers.keys())
        for header, value in response.headers.items():
            if log: Add(f"Header: {white}{header:<{max_len}}{red} Value: {white}{value}")
            headers_dict[header] = value
        if headers_dict: json_format = json.dumps({"HTTP headers": headers_dict})
    except: pass
    return headers_dict, json_format

def TargetAnalyzeCookies(response, log=True):
    results = []
    json_format = None
    try:
        if not response: return results, json_format
        max_len = max((len(c.name) for c in response.cookies), default=0)
        for c in response.cookies:
            secure = c.secure
            http_only = "HttpOnly" in str(c._rest)
            if log: Add(f"Cookie: {white}{c.name:<{max_len}}{red} Secure: {white}{str(secure):<5}{red} HttpOnly: {white + str(http_only)}")
            results.append({"name": c.name, "secure": secure, "http_only": http_only})
        if results: json_format = json.dumps({"Cookies": results})
    except: pass
    return results, json_format

def TargetDetectTechnologies(response, log=True):
    detected = []
    json_format = None
    try:
        if not response: return detected, json_format
        soup = bs4.BeautifulSoup(response.text, "html.parser")
        h = response.headers
        if "server" in h:
            tech = f"Server {h['server']}"
            if log: Add(f"Detected technology: {white}{tech}")
            detected.append(tech)
        if "x-powered-by" in h:
            tech = h["x-powered-by"]
            if log: Add(f"Detected technology: {white}{tech}")
            detected.append(tech)
        for s in soup.find_all("script", src=True):
            src = s["src"].lower()
            if "jquery" in src:
                tech = "jQuery"
                if log: Add(f"Detected technology: {white}{tech}")
                detected.append(tech)
            if "bootstrap" in src:
                tech = "Bootstrap"
                if log: Add(f"Detected technology: {white}{tech}")
                detected.append(tech)
        if detected: json_format = json.dumps({"Technologies": detected})
    except: pass
    return detected, json_format

def TargetDetectWaf(response, log=True):
    detected_waf = []
    json_format = None
    try:
        if not response: return detected_waf, json_format

        waf_signatures = {
            "cloudflare": ("cf-ray", "cf-cache-status", "__cfduid", "cloudflare"),
            "akamai": ("akamai", "x-akamai", "ak_bmsc", "akamaighost"),
            "incapsula": ("incap_ses", "visid_incap", "_incap_"),
            "imperva": ("imperva",),
            "f5": ("f5_", "bigip", "BIGipServer", "x-cnection", "TS"),
            "aws": ("x-amz-cf-id", "x-amz-cf-pop", "x-amz-request-id", "awselb"),
            "modsecurity": ("mod_security", "modsec", "naxsi", "NOYB"),
            "cloudfront": ("cloudfront",),
            "barracuda": ("barracuda", "X-Barracuda-", "barra_counter_session"),
            "securitytrails": ("securitytrails",),
            "stackpath": ("stackpath", "x-stckpt"),
            "distil": ("distil_r_captcha", "distil_r_cid"),
            "sucuri": ("sucuri", "x-sucuri"),
            "fortiweb": ("fortigate", "fortiweb"),
            "wordfence": ("wordfence",)
        }

        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        cookies = {k.lower(): v.lower() for k, v in response.cookies.get_dict().items()}

        for waf, signs in waf_signatures.items():
            for s in signs:
                if any(s in h or s in v for h, v in headers.items()) or any(s in c for c in cookies):
                    detected_waf.append(waf)
                    if log: Add(f"WAF detected: {white}{waf}{red}")
                    break

        detected_waf = list(set(detected_waf))
        if detected_waf:
            json_format = json.dumps({"WAF": detected_waf})
    except: pass
    return detected_waf, json_format

def IpType(ip, log=True):
    status = None
    json_format = None
    if not IpStatus(ip): return status, json_format
    if ":" in ip: status = "ipv6"
    elif "." in ip: status = "ipv4"
    if log: Add(f"IP type: {white}{'ipv6' if ':' in ip else 'ipv4'}{red}")
    if status: json_format = json.dumps({"IP type": status})
    return status, json_format

def IpPrivate(ip, log=True):
    status = None
    json_format = None
    try:
        ip_obj = ipaddress.ip_address(ip)
        status = (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast)
        if log: Add(f"IP private: {white}{status}")
        json_format = json.dumps({"IP private": status})
    except:
        pass
    return status, json_format

def IpGetLookup(ip, session, http_timeout, log=True):
    status = country = country_code = region = region_code = zip = city = latitude = longitude = timezone = isp = org = as_host = None
    json_format = None
    vars = {}

    if IpStatus(ip):
        try:
            api          = session.get(f"http://{api_ip_lookup}/json/{ip}", timeout=http_timeout).json()
            status       = "Valid" if api.get("status") == "success" else "Invalid"
            country      = api.get("country", None)
            country_code = api.get("countryCode", None)
            region       = api.get("regionName", None)
            region_code  = api.get("region", None)
            zip          = api.get("zip", None)
            city         = api.get("city", None)
            latitude     = api.get("lat", None)
            longitude    = api.get("lon", None)
            timezone     = api.get("timezone", None)
            isp          = api.get("isp", None)
            org          = api.get("org", None)
            as_host      = api.get("as", None)
        except: pass

        temp_vars = {
            "IP country"     : country,
            "IP country code": country_code,
            "IP region"      : region,
            "IP region code" : region_code,
            "IP zip"         : zip,
            "IP city"        : city,
            "IP latitude"    : latitude,
            "IP longitude"   : longitude,
            "IP timezone"    : timezone,
            "IP isp"         : isp,
            "IP org"         : org,
            "IP as"          : as_host
        }
        vars = {k: str(v) for k, v in temp_vars.items() if v is not None}

        if log:
            for name, value in vars.items(): Add(f"{name}: {white + str(value)}")
        if vars: json_format = json.dumps(vars)

    return vars, json_format

def IpGetDns(ip, log=True):
    hostname = None
    json_format = None
    
    if not IpStatus(ip): return hostname, json_format
    try:
        result = socket.gethostbyaddr(ip)
        hostname = result[0]
        aliases = result[1]
        
        if hostname:
            if log:
                Add(f"DNS: {white}{hostname}")
                if aliases:
                    for alias in aliases: 
                        Add(f"DNS alias: {white}{alias}")
            json_data = {"DNS": hostname}
            if aliases: json_data["DNS aliases"] = aliases
            json_format = json.dumps(json_data)
    except: pass
    return hostname, json_format

def DomainAge(domain, log=True):
    domain_age_days = None
    json_format     = None
    
    try:
        w = whois.whois(domain)
        domain_whois_creation = w.creation_date
        if isinstance(domain_whois_creation, list): domain_whois_creation = domain_whois_creation[0]
        if domain_whois_creation is not None:
            if hasattr(domain_whois_creation, "tzinfo") and domain_whois_creation.tzinfo is not None:
                domain_whois_creation = domain_whois_creation.replace(tzinfo=None)
            now = datetime.datetime.utcnow()
            domain_age_days = str((now - domain_whois_creation).days) + " days"
        else: domain_age_days = None
        
        if domain_age_days:
            if log: Add(f"Domain age: {white}{domain_age_days}")
            json_format = json.dumps({"Domain age": domain_age_days})
    except: pass
    return domain_age_days, json_format

def DomainDnsRecords(domain, log=True):
    records     = None
    json_format = None
    found = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR"]
    
    try:
        resolver = dns.resolver.Resolver()
        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                found[record_type] = [str(rdata).replace("\"", "") for rdata in answers]
            except: continue
        if found:
            records = found
            if log:
                for record_type, values in records.items():
                    for value in values: Add(f"DNS {record_type}: {white}{value}")
            json_format = json.dumps({"DNS records": records})
    except: pass
    return records, json_format

def DomainCertificateTransparency(session, domain, http_timeout, log=True):
    certificates = None
    json_format  = None
    found = []
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = session.get(url, timeout=http_timeout)
        if response.status_code == 200:
            data = response.json()
            seen = set()
            for entry in data:
                cert_info = {
                    "issuer": entry.get("issuer_name"),
                    "not_before": entry.get("not_before"),
                    "not_after": entry.get("not_after"),
                    "common_name": entry.get("common_name"),
                    "name_value": entry.get("name_value")
                }
                cert_info = {k: v for k, v in cert_info.items() if v is not None and v != ""}
                if cert_info:
                    cert_id = f"{cert_info.get('issuer', '')}_{cert_info.get('not_before', '')}_{cert_info.get('common_name', '')}"
                    if cert_id not in seen:
                        seen.add(cert_id)
                        found.append(cert_info)
        if found:
            certificates = found
            if log:
                for cert in certificates[:10]: Add(f"Certificate CN: {white}{cert.get('common_name', 'N/A')}{red} Issuer: {white}{cert.get('issuer', 'N/A')}")
                if len(certificates) > 10: Info(f"And {white}{len(certificates) - 10}{red} more certificates (all displayed if the output is json)")
                Add(f"Total certificates: {white}{len(certificates)}")
            json_format = json.dumps({"Certificates": certificates})
    except: pass
    return certificates, json_format

def IpGetPingAndLatency(ip, socket_timeout=default_socket_timeout, interval=default_interval, log=True, port=default_port, status=None, loop=None, bytes=default_bytes, icmp_timeout=0):
    ping_status = False
    latency     = "timeout"
    json_format = None

    if not IpStatus(ip): return ping_status, latency, json_format
    ip_type = IpType(ip, log=False)

    def ICMP():
        nonlocal ping_status, latency, ip_type
        try:
            if icmp_timeout:
                if os_name == "Windows":
                    if ip_type == "ipv6": cmd = ["ping", "-6", "-n", "1", "-w", "1000", ip]
                    else: cmd = ["ping", "-n", "1", "-w", "300", ip]
                else:
                    if ip_type == "ipv6": cmd = ["ping", "-6", "-c", "1", "-W", "1", ip]
                    else: cmd = ["ping", "-c", "1", "-W", "1", ip]
            else:
                if os_name == "Windows":
                    if ip_type == "ipv6": cmd = ["ping", "-6", "-n", "1", "-l", str(bytes), ip]
                    else: cmd = ["ping", "-n", "1", "-l", str(bytes), ip]
                else:
                    if ip_type == "ipv6": cmd = ["ping", "-6", "-c", "1", "-s", str(bytes), ip]
                    else: cmd = ["ping", "-c", "1", "-s", str(bytes), ip]

            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            ping_status = result.returncode == 0

            if ping_status:
                out = result.stdout.lower().splitlines()
                for line in out:
                    if "ttl=" in line:
                        m_eq = re.search(r"=\s*([\d\.]+)\s*ms", line)
                        m_lt = re.search(r"<\s*([\d\.]+)\s*ms", line)

                        if m_lt: latency = "<1ms"
                        elif m_eq: latency = str(m_eq.group(1)) + "ms"
                        break
            else: latency = "timeout"
            if log:
                Add(f"IP ping ICMP: {white + str(ping_status)}")
                Add(f"IP latency ICMP: {white + str(latency)}")
        except:
            latency = "timeout"
            ping_status = False
        return ping_status, latency

    def TCP():
        nonlocal ping_status, latency, ip_type
        start = time.time()
        try:
            family = socket.AF_INET6 if ip_type == "ipv6" else socket.AF_INET
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(socket_timeout)
            s.connect((ip, port))
            s.close()
            latency = str(round((time.time() - start) * 1000)) + "ms"
            ping_status = True
        except:
            latency = "timeout"
            ping_status = False
        return ping_status, latency

    if status == "ICMP":
        if loop:
            while True:
                ping_status, latency = ICMP()
                if ping_status: status = "succeed"
                else: status = "failed"
                Add(f"IP: {white + str(ip) + red} Bytes: {white + str(bytes) + red} Protocol: {white + 'ICMP' + red} Status: {white + status + red} Latency: {white + str(latency) + red}")
                time.sleep(interval)
        else: 
            ping_status, latency = ICMP()
            
    elif status == "TCP":
        if loop:
            while True:
                ping_status, latency = TCP()
                if ping_status: status = "succeed"
                else: status = "failed"
                Add(f"IP: {white + str(ip) + red} Port: {white + str(port) + red} Protocol: {white + 'TCP' + red} Status: {white + status + red} Latency: {white + str(latency) + red}")
                time.sleep(interval)
        else: ping_status, latency = TCP()

    if ping_status is not None and latency is not None:
        json_format = json.dumps({"IP ping ICMP": ping_status, "IP latency ICMP": latency})
    return ping_status, latency, json_format

def IpDetectHostingProvider(ip, proxy=None, log=True):
    provider = None
    json_format = None
    try:
        obj = ipwhois.IPWhois(ip)
        lookup_kwargs = {"asn_methods": ["whois"]}
        if proxy:
            lookup_kwargs["proxy"] = proxy
        res = obj.lookup_rdap(**lookup_kwargs)
        provider = res.get("network", {}).get("name")
        if log and provider: Add(f"Hosting provider: {white}{provider}")
        if provider: json_format = json.dumps({"Hosting provider": provider})
    except: pass
    return provider, json_format

def IpGetPort(ip, socket_timeout=None, port=None, all=None, mass_scan=False, port_default=None, log=True, stats_pressed=None, protocol_scan=None):
    udp_payloads = {
        7:  [b"ping"], 9:  [b"\xff" * 32], 13: [b"\r\n"], 17: [b"qotd"], 19: [b"\x00"], 37: [b"\x00"], 42: [b"\x00" * 4],
        53: [
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
            b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06cloud\x03com\x00\x00\x01\x00\x01",
            b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        ],
        67: [b"\x01\x01\x06\x00" + b"\x00" * 236], 68: [b"\x01\x01\x06\x00" + b"\x00" * 236], 
        69: [b"\x00\x01test\x00octet\x00"], 111: [b"\x80\x00\x00\x28" + b"\x00" * 36], 
        123: [b"\x1b" + b"\x00" * 47], 137: [b"\x81\x10" + b"\x00" * 50], 138: [b"\x00" * 50],
        161: [
            b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\x7b\x0e\x3f\x02\x01\x00\x02\x01\x00\x30\x0b\x30",
            b"\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00\x30\x29\x02\x01\x00\x04\x06public\xa0\x1c\x02\x04\x00\x00\x00",
            b"\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
        ],
        162: [b"\x30\x2c\x02\x01\x00\x04\x06public\xa4\x1f"], 389:[b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"],
        500: [b"\x01\x10\x02\x00\x00\x00\x00\x00"], 514: [b"\x00\x00"], 520:[b"\x02\x02\x00\x00"], 
        623: [b"\x06\x00\xff\x07\x00\x00\x00\x00"], 1194: [b"\x38\x01\x00\x00"], 1434:[b"\x02"],
        1900: [b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n"],
        2049: [b"\x80\x00\x00\x28"], 2082: [b"GET / HTTP/1.0\r\n\r\n"], 2083: [b"GET / HTTP/1.0\r\n\r\n"], 3478:[b"\x00\x01\x00\x00"],
        3702: [b"<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\"></e:Envelope>"], 4500:[b"\x00\x00\x00\x00"],
        5004: [b"\x80\xe0\x00\x01"], 5060: [b"OPTIONS sip:test SIP/2.0\r\nVia: SIP/2.0/UDP test\r\n\r\n"],
        5353: [b"\x00\x00\x00\x00"], 5683: [b"\x40\x01\x00\x00"], 6000: [b"\x6c\x00\x0b\x00"], 11211: [b"stats\r\n"],
        27015: [b"\xff\xff\xff\xffstatus\x00"]
    }

    udp_generic_payloads = [
        b"\x00", b"\xff", b"\x01\x02\x03\x04", b"\x10\x20\x30\x40", b"\xaa\xbb\xcc\xdd", b"\x00" * 8, b"\xff" * 8
    ]

    if not IpStatus(ip): return None, None
    if port_default and port_default not in data_ports: data_ports[port_default] = "Custom Service"

    if all: ports_to_scan = range(1, 65536)
    elif isinstance(port, str):
        if "-" in port:
            start, end = port.split("-")
            ports_to_scan = range(int(start), int(end) + 1)
        else: ports_to_scan = [int(p) for p in port.split(",")]
    elif isinstance(port, int): ports_to_scan = [port]
    else: 
        Wait(f"Scanning all ports by default..")
        ports_to_scan = sorted(data_default_ports["default_ports"])

    ports_to_scan = sorted(set(int(p) for p in ports_to_scan))
    tcp_port_stats = {"Open": [],                      "Filtered": [], "Closed": []}
    udp_port_stats = {"Open": [], "Open/Filtered": [], "Filtered": [], "Closed": []}
    tcp_summary = udp_summary = summary = {}
    socket_max_workers = 300
    lock = threading.Lock()

    def ScanPortTcp(port):
        status = latency = None
        try:
            start = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            r = s.connect_ex((ip, port))
            latency = str(round((time.time() - start) * 1000, 2)) + "ms"

            if r == 0:
                status = "Open"
                s.close()
                return status, latency

            _, writable, _ = select.select([], [s], [], socket_timeout)
            if not writable:
                status = "Filtered"
                s.close()
                return status, latency

            err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            latency = str(round((time.time() - start) * 1000, 2)) + "ms"
            
            if err == 0: status = "Open"
            elif err in (errno.ECONNREFUSED, 10061): status = "Closed"
            else: status = "Filtered"
            s.close()
            return status, latency
        except:
            try: s.close()
            except: pass
            return status, latency
        
    def ScanPortUdp(port):
        payloads = udp_payloads.get(port, udp_generic_payloads)
        status = latency = None

        for attempt in range(6):
            timeout = socket_timeout * (1 + attempt * 0.5)
            payload = random.choice(payloads)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)

            try:
                s.connect((ip, port))
                start = time.time()
                s.send(payload)
                s.recv(65507)
                latency = str(round((time.time() - start) * 1000, 2)) + "ms"
                status = "Open"
                s.close()
                return status, latency
            except socket.timeout: status = "Open/Filtered"
            except OSError as e:
                if e.errno == errno.ECONNREFUSED:
                    latency = str(round((time.time() - start) * 1000, 2)) + "ms"
                    status = "Closed"
                    s.close()
                    return status, latency
                status = "Filtered"
            finally:
                try: s.close()
                except: pass

            time.sleep(0.05 + random.random() * 0.1)
        
        latency = "timeout"
        return status, latency

    def StatusPort(port, protocol, status, latency, service):
        if status == "Open":
            with lock: 
                if protocol   == "TCP": tcp_port_stats[status].append({"Port": port, "Protocol": protocol, "Status": status, "Latency": latency, "Service": service})
                elif protocol == "UDP": udp_port_stats[status].append({"Port": port, "Protocol": protocol, "Status": status, "Latency": latency, "Service": service})
            if log: Add(f"{white}{port:<7} {protocol:<10} {status:<14} {latency:<10} {service}")
        elif status == "Open/Filtered":
            with lock: 
                if protocol   == "TCP": tcp_port_stats[status].append({"Port": port, "Protocol": protocol, "Status": status, "Latency": "timeout", "Service": service})
                elif protocol == "UDP": udp_port_stats[status].append({"Port": port, "Protocol": protocol, "Status": status, "Latency": "timeout", "Service": service})
            if not mass_scan and log: Add(f"{white}{port:<7} {protocol:<10} {status:<14} {'timeout':<10} {service}")
        elif status == "Filtered":
            with lock: 
                if protocol   == "TCP": tcp_port_stats[status].append({"Port": port, "Protocol": protocol, "Status": status, "Latency": "timeout", "Service": service})
                elif protocol == "UDP": udp_port_stats[status].append({"Port": port, "Protocol": protocol, "Status": status, "Latency": "timeout", "Service": service})
            if not mass_scan and log: Add(f"{white}{port:<7} {protocol:<10} {status:<14} {'timeout':<10} {service}")
        elif status == "Closed":
            with lock: 
                if protocol   == "TCP": tcp_port_stats[status].append({"Port": port, "Protocol": protocol, "Status": status, "Latency": latency, "Service": service})
                elif protocol == "UDP": udp_port_stats[status].append({"Port": port, "Protocol": protocol, "Status": status, "Latency": latency, "Service": service})
            if not mass_scan and log: Add(f"{white}{port:<7} {protocol:<10} {status:<14} {latency:<10} {service}")

    def ScanPort(port):
        service = data_ports.get(str(port), "Unknown")
        if stats_pressed: state["completed"] += 1
        if "TCP" in protocol_scan:
            status, latency = ScanPortTcp(port)
            StatusPort(port, "TCP", status, latency, service)
        if "UDP" in protocol_scan:
            status, latency = ScanPortUdp(port)
            StatusPort(port, "UDP", status, latency, service)

    if stats_pressed:
        state = {"stop": False, "completed": 0, "completed_total": len(ports_to_scan)}
        StartThread(StatsPressed, state, time_start=time.time())

    if log: print(f"{red}{'':<14} {'Port:':<7} {'Protocol:':<10} {'Status:':<14} {'Latency:':<10} Service:{reset}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=socket_max_workers) as exe: exe.map(ScanPort, ports_to_scan)

    if stats_pressed: state["stop"] = True
    if log: Info(f"Open: {white}{len(tcp_port_stats['Open']) + len(udp_port_stats['Open'])}{red} Closed: {white}{len(tcp_port_stats['Closed']) + len(udp_port_stats['Closed'])}{red} Filtered (no response): {white}{len(tcp_port_stats['Filtered'])}")

    if "TCP" in protocol_scan:
        if not mass_scan: tcp_summary = {"TCP Port": tcp_port_stats}
        else: tcp_summary = {"TCP Port": {"Open": tcp_port_stats["Open"], "Closed": len(tcp_port_stats["Closed"]), "Filtered": len(tcp_port_stats["Filtered"])}}
    
    if "UDP" in protocol_scan:
        if not mass_scan: udp_summary = {"UDP Port": udp_port_stats}
        else: udp_summary = {"UDP Port": {"Open": udp_port_stats["Open"], "Open/Filtered": len(udp_port_stats["Open/Filtered"]), "Closed": len(udp_port_stats["Closed"]), "Filtered": len(udp_port_stats["Filtered"])}}

    if tcp_summary: summary.update(tcp_summary)
    if udp_summary: summary.update(udp_summary)
    json_format = json.dumps(summary, indent=4)
        
    return tcp_port_stats, udp_port_stats, json_format

def IpGetServiceBanner(ip, ports, socket_timeout, log=True):
    banners = {}
    json_format = None
    try:
        if not IpStatus(ip): return banners, json_format
        if log: Wait("Search for open port banners..")
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(socket_timeout)
                s.connect((ip, port))
                banner = s.recv(8192).decode(errors="ignore").strip()
                s.close()
                if banner:
                    banners[port] = banner
                    if log: Add(f"Port: {white}{str(port):<5}{red} Banner: {white + str(banner)}")
            except: continue
        if not banners and log: Info("No banners detected.")
        if banners: json_format = json.dumps({"Banners": banners})
    except: pass
    return banners, json_format

def FingerprintBackend(response, url, log=True):
    detected_backend = None
    json_format = None
    try:
        if not response: return detected_backend, json_format

        backend = {}

        server = response.headers.get("Server", "").lower()
        powered = response.headers.get("X-Powered-By", "").lower()
        text = response.text.lower()
        headers_str = str(response.headers).lower()

        if "apache" in server: backend["server"] = "apache"
        elif "nginx" in server: backend["server"] = "nginx"
        elif "iis" in server or "microsoft" in server: backend["server"] = "iis"
        elif "cloudflare" in server: backend["server"] = "cloudflare"

        if "php" in powered: backend["lang"] = "php"
        elif "asp.net" in powered: backend["lang"] = "asp.net"
        elif ".jsp" in url or "jsessionid" in text: backend["lang"] = "java"
        elif "express" in powered or "x-powered-by: express" in headers_str: backend["lang"] = "nodejs"

        frameworks = {
            "laravel": ["laravel_session", "xsrf-token"],
            "django": ["csrftoken", "django"],
            "rails": ["_rails", "_session_id"],
            "wordpress": ["wp-content", "wp-includes"],
            "joomla": ["joomla", "option=com_"],
            "drupal": ["drupal", "x-drupal-cache"]
        }

        for fw, signs in frameworks.items():
            if any(s in text or s in headers_str for s in signs):
                backend["framework"] = fw
                break

        backend = {k: v for k, v in backend.items() if v is not None}

        if backend:
            detected_backend = backend
            json_format = json.dumps({"URL backend": backend})
            if log: Add(f"URL backend: {white}{' / '.join(backend.values())}")
    except: pass
    return detected_backend, json_format

def IpOsFingerprint(ip, open_ports, socket_timeout, log=True):
    os_votes = {}
    details = {}
    final_os = confidence = None
    json_format = None

    def Vote(os_name, weight, source):
        if not os_name or os_name == "Unknown": return
        for os_part in os_name.split("/"):
            os_clean = os_part.strip().split("(")[0].strip()
            if os_clean and os_clean != "Unknown":
                os_votes[os_clean] = os_votes.get(os_clean, 0) + weight
                if os_clean not in details: details[os_clean] = []
                details[os_clean].append(f"{source}(+{weight})")
    
    try:
        if not open_ports: return None, None, None
        
        TTL_SIGS = {32: "Windows 9x", 64: "Linux", 128: "Windows", 255: "Cisco"}
        for port in open_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(socket_timeout)
                s.connect((ip, port))
                try: 
                    ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                    for std in [32, 64, 128, 255]:
                        if ttl <= std:
                            Vote(TTL_SIGS.get(std), 3, f"TTL:{port}")
                            break
                except: pass
                s.close()
            except: continue
        
        WIN_SIGS = {5840: "Windows 10", 8192: "Windows XP", 65535: "Linux", 16384: "Windows Server", 4096: "BSD", 14600: "OpenBSD", 32768: "Solaris"}
        for port in open_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(socket_timeout)
                s.connect((ip, port))
                win = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                s.close()
                if win:
                    os_guess = WIN_SIGS.get(win)
                    if not os_guess:
                        if win >= 65535: os_guess = "Linux"
                        elif 8000 <= win < 20000: os_guess = "Windows"
                        elif win < 8000: os_guess = "BSD"
                    Vote(os_guess, 2, f"TCPWin:{port}")
            except: continue
        
        for port in open_ports:
            try:
                opts = []
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(socket_timeout)
                try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); opts.append("NODELAY")
                except: pass
                try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1); opts.append("QUICKACK")
                except: pass
                s.connect((ip, port))
                try: s.getsockopt(socket.IPPROTO_TCP, 30); opts.append("TS")
                except: pass
                s.close()
                if "QUICKACK" in opts: Vote("Linux", 2, f"TCPOpt:{port}")
                elif len(opts) >= 2: Vote("Linux", 1, f"TCPOpt:{port}")
                elif len(opts) <= 1: Vote("Windows", 1, f"TCPOpt:{port}")
            except: continue
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.settimeout(socket_timeout)
            pid = random.randint(1, max_port)
            header = struct.pack("!BBHHH", 8, 0, 0, pid, 1)
            data = struct.pack("!d", time.time())
            checksum = sum(struct.unpack("!%dH" % (len(header + data) // 2), header + data))
            checksum = (checksum >> 16) + (checksum & 0xffff)
            checksum = ~checksum & 0xffff
            header = struct.pack("!BBHHH", 8, 0, checksum, pid, 1)
            s.sendto(header + data, (ip, 0))
            reply, _ = s.recvfrom(1024)
            s.close()
            ttl = struct.unpack("!B", reply[8:9])[0]
            if ttl <= 64: Vote("Linux", 2, "ICMP")
            elif ttl <= 128: Vote("Windows", 2, "ICMP")
            else: Vote("Cisco", 2, "ICMP")
        except: pass
        
        BANNER_PATTERNS = {
            r"Ubuntu": "Ubuntu", r"Debian": "Debian", r"CentOS": "CentOS", r"Red Hat": "Red Hat",
            r"Fedora": "Fedora", r"FreeBSD": "FreeBSD", r"OpenBSD": "OpenBSD", r"Microsoft": "Windows",
            r"Win32": "Windows", r"Win64": "Windows", r"IIS": "Windows Server",
            r"Apache.*Ubuntu": "Ubuntu", r"Apache.*Debian": "Debian", r"Apache.*CentOS": "CentOS",
            r"Apache.*Win": "Windows", r"nginx.*Ubuntu": "Ubuntu", r"nginx.*Debian": "Debian",
            r"OpenSSH.*Ubuntu": "Ubuntu", r"OpenSSH.*Debian": "Debian", r"OpenSSH.*FreeBSD": "FreeBSD",
            r"OpenSSH.*CentOS": "CentOS", r"vsftpd": "Linux", r"FileZilla": "Windows",
            r"Exim": "Linux", r"Postfix": "Linux", r"Sendmail": "Unix",
            r"Microsoft ESMTP": "Windows Server", r"Samba": "Linux", r"ProFTPD.*Debian": "Debian"
        }
        
        for port in open_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(socket_timeout)
                s.connect((ip, port))
                banner = s.recv(2048).decode(errors="ignore").strip()
                s.close()
                if banner:
                    for pattern, os_name in BANNER_PATTERNS.items():
                        if re.search(pattern, banner, re.I):
                            Vote(os_name, 4, f"Banner:{port}")
                            break
            except: continue
        
        HTTP_PATTERNS = {
            r"Microsoft-IIS/10": "Windows Server 2016", r"Microsoft-IIS/8": "Windows Server 2012",
            r"Microsoft-IIS/7": "Windows Server 2008", r"Microsoft-IIS": "Windows Server",
            r"Win32": "Windows", r"Win64": "Windows", r"Ubuntu": "Ubuntu", r"Debian": "Debian",
            r"CentOS": "CentOS", r"Red Hat": "Red Hat", r"Apache.*Ubuntu": "Ubuntu",
            r"Apache.*Debian": "Debian", r"Apache.*CentOS": "CentOS", r"Apache.*Win": "Windows",
            r"nginx.*Ubuntu": "Ubuntu", r"nginx.*Debian": "Debian", r"nginx.*CentOS": "CentOS"
        }
        
        for port in open_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(socket_timeout)
                if port in [port_https, 8443]:
                    ctx = _ssl_scan_context()
                    s = ctx.wrap_socket(s, server_hostname=ip)
                s.connect((ip, port))
                s.sendall(f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
                resp = s.recv(2048).decode(errors="ignore")
                s.close()
                if resp:
                    server = powered = ""
                    for line in resp.split("\r\n"):
                        if line.lower().startswith("server:"): server = line.split(":", 1)[1].strip()
                        if line.lower().startswith("x-powered-by:"): powered = line.split(":", 1)[1].strip()
                    combined = server + " " + powered
                    for pattern, os_name in HTTP_PATTERNS.items():
                        if re.search(pattern, combined, re.I):
                            Vote(os_name, 3, f"HTTP:{port}")
                            break
            except: continue
        
        for port in open_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(socket_timeout)
                s.connect((ip, port))
                negotiate = b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"
                negotiate += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe"
                negotiate += b"\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f"
                negotiate += b"\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02"
                s.send(negotiate)
                resp = s.recv(4096)
                s.close()
                if resp:
                    if b"Windows 11" in resp: Vote("Windows 11", 6, f"SMB:{port}")
                    elif b"Windows 10" in resp: Vote("Windows 10", 6, f"SMB:{port}")
                    elif b"Windows 8.1" in resp: Vote("Windows 8", 6, f"SMB:{port}")
                    elif b"Windows 8" in resp: Vote("Windows 8", 6, f"SMB:{port}")
                    elif b"Windows 7" in resp: Vote("Windows 7", 6, f"SMB:{port}")
                    elif b"Windows Server 2022" in resp: Vote("Windows Server 2022", 6, f"SMB:{port}")
                    elif b"Windows Server 2019" in resp: Vote("Windows Server 2019", 6, f"SMB:{port}")
                    elif b"Windows Server 2016" in resp: Vote("Windows Server 2016", 6, f"SMB:{port}")
                    elif b"Windows Server 2012" in resp: Vote("Windows Server 2012", 6, f"SMB:{port}")
                    elif b"Windows Server 2008" in resp: Vote("Windows Server 2008", 6, f"SMB:{port}")
                    elif b"Windows" in resp: Vote("Windows", 5, f"SMB:{port}")
                    elif b"Samba" in resp: Vote("Linux", 5, f"SMB:{port}")
            except: continue
        
        for port in open_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(socket_timeout)
                s.connect((ip, port))
                banner = s.recv(1024).decode(errors="ignore").strip()
                s.close()
                if banner:
                    if "Ubuntu" in banner: Vote("Ubuntu", 5, f"SSH:{port}")
                    elif "Debian" in banner: Vote("Debian", 5, f"SSH:{port}")
                    elif "FreeBSD" in banner: Vote("FreeBSD", 5, f"SSH:{port}")
                    elif "OpenBSD" in banner: Vote("OpenBSD", 5, f"SSH:{port}")
                    elif "CentOS" in banner: Vote("CentOS", 5, f"SSH:{port}")
                    elif "Red Hat" in banner: Vote("Red Hat", 5, f"SSH:{port}")
                    elif "Fedora" in banner: Vote("Fedora", 5, f"SSH:{port}")
            except: continue
        
        for port in open_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(socket_timeout)
                s.connect((ip, port))
                try:
                    mss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
                    if mss == 1460: Vote("Linux", 1, f"MSS:{port}")
                    elif mss == 1440: Vote("Windows", 1, f"MSS:{port}")
                except: pass
                s.close()
            except: continue
        
        for port in open_ports:
            try:
                s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s1.settimeout(socket_timeout)
                s1.connect((ip, port))
                time.sleep(0.05)
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(socket_timeout)
                s2.connect((ip, port))
                s1.close()
                s2.close()
                Vote("Linux", 1, f"ISN:{port}")
            except: continue
        
        if os_votes:
            final_os = max(os_votes, key=os_votes.get)
            total = sum(os_votes.values())
            confidence = round((os_votes[final_os] / total) * 100, 1)
            
            if log:
                Add(f"OS fingerprint: {white}{final_os}")
                Add(f"OS confidence: {white}{confidence}%")
            
            json_format = json.dumps({
                "OS fingerprint": final_os,
                "OS confidence": f"{confidence}%",
                "OS votes": os_votes,
                "OS detection details": details
            })        
    except: pass

    return final_os, confidence, json_format

def DetectTarget(value):
    """
        http://example.com      : url
       https://example.com      : url
        http://example.com/page : url/page
       https://example.com/page : url/page
               example.com      : domain
               example.com/page : domain/page

            localhost           : localhost
            localhost/page      : localhost/page
            localhost:0000      : localhost:port
     http://localhost:0000      : localhost:port
    https://localhost:0000      : localhost:port
            localhost:0000/page : localhost:port/page
     http://localhost:0000/page : localhost:port/page
    https://localhost:0000/page : localhost:port/page

              0.0.0.0           : ip
              0.0.0.0:0000      : ip:port
       http://0.0.0.0:0000      : ip:port
      https://0.0.0.0:0000      : ip:port
              0.0.0.0:0000/page : ip:port/page
       http://0.0.0.0:0000/page : ip:port/page
      https://0.0.0.0:0000/page : ip:port/page
    """
    
    value = value.strip().lower()

    url_match = re.match(r"^(https?://)(.+)", value)
    if url_match:
        host_part = url_match.group(2)
        if re.match(r"^(localhost)(:\d+)?", host_part): return "localhost:port/page" if ":" in host_part and "/" in host_part else ("localhost/page" if "/" in host_part else "localhost:port" if ":" in host_part else "localhost")
        try:
            ip_only = host_part
            if host_part.startswith("[") and "]:" in host_part: ip_only = host_part.split("]")[0][1:]
            elif ":" in host_part and host_part.count(":") > 1: ip_only = host_part
            elif ":" in host_part and host_part.count(":") == 1: ip_only = host_part.split(":")[0]
            ipaddress.ip_address(ip_only)
            if value.startswith("[") and "]:" in value: return "ip:port/page" if "/" in value else "ip:port"
            if ip_only.count(":") > 1: return "ip"
            return "ip:port/page" if "/" in host_part else "ip:port"
        except: pass
        return "url/page" if "/" in host_part else "url"
    try:
        ip_only = value
        if value.startswith("[") and "]:" in value: ip_only = value.split("]")[0][1:]
        elif ":" in value and value.count(":") > 1: ip_only = value
        elif ":" in value and value.count(":") == 1: ip_only = value.split(":")[0]
        ipaddress.ip_address(ip_only)
        if value.startswith("[") and "]:" in value: return "ip:port/page" if "/" in value else "ip:port"
        if ip_only.count(":") > 1: return "ip"
        return "ip:port/page" if "/" in value else ("ip:port" if ":" in value else "ip")
    except: pass
    if re.match(r"^(localhost)(:\d+)?", value): return "localhost:port/page" if ":" in value and "/" in value else ("localhost/page" if "/" in value else "localhost:port" if ":" in value else "localhost")
    domain_part = value.split("/")[0]
    if re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", domain_part): return "domain/page" if "/" in value else "domain"
    return "unknown"
