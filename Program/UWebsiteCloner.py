# Copyright (c) RedTiger by Loxy0devlp
# Licensed under the MIT License.
# See LICENSE file in the project root for full license text.

from Config.Utils import *
from Program.Utils.NetworkScanningUtils import *

def SanitizeXmlString(text):
    if not text: return text
    return re.sub(r'[^\x09\x0A\x0D\x20-\x7E\u00A0-\uD7FF\uE000-\uFFFD]', '', text)

def GetMimeTypeFromUrl(url):
    path_lower = urllib.parse.urlparse(url).path.lower()
    if path_lower.endswith(".png"):                                 return "image/png"
    if path_lower.endswith(".jpg") or path_lower.endswith(".jpeg"): return "image/jpeg"
    if path_lower.endswith(".gif"):                                 return "image/gif"
    if path_lower.endswith(".svg"):                                 return "image/svg+xml"
    if path_lower.endswith(".webp"):                                return "image/webp"
    if path_lower.endswith(".woff"):                                return "font/woff"
    if path_lower.endswith(".woff2"):                               return "font/woff2"
    if path_lower.endswith(".ttf"):                                 return "font/ttf"
    if path_lower.endswith(".otf"):                                 return "font/otf"
    if path_lower.endswith(".eot"):                                 return "application/vnd.ms-fontobject"
    if path_lower.endswith(".css"):                                 return "text/css"
    if path_lower.endswith(".js"):                                  return "application/javascript"
    return "application/octet-stream"

def FetchUrlContent(session, url, http_timeout):
    for _ in range(3):
        try:
            response = session.get(url, timeout=http_timeout)
            if response.status_code == 200: return response.content
            elif response.status_code == 403: return None
        except requests.exceptions.Timeout: continue
        except requests.exceptions.RequestException: return None
    return None

def RenderFullPageWithRequests(state, session, target, http_timeout):
    response = None
    try:
        response = session.get(target, timeout=http_timeout)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        status_code = response.status_code if response is not None else "unknown"
        Error(f"HTTP error {status_code}: {white}{e}")
        return None, None
    except requests.exceptions.RequestException as e:
        Error(f"Request error: {white}{e}")
        return None, None

    full_page_html = SanitizeXmlString(response.content.decode("utf-8", "ignore"))
    Info(f"HTML retrieved.")
    state["completed"] += 1

    match        = re.search(r'<title>(.*?)</title>', full_page_html, re.IGNORECASE | re.DOTALL)
    page_title   = match.group(1).strip() if match else "page"
    return full_page_html, page_title

def InlineCssResourceUrls(target, css_content, resource_data_map):
    def ReplaceUrl(match):
        resource_url = match.group(1).strip('\'"')
        full_url     = urllib.parse.urljoin(target, resource_url)
        if full_url in resource_data_map:
            mime_type   = GetMimeTypeFromUrl(full_url)
            base64_data = base64.b64encode(resource_data_map[full_url]).decode()
            return f"url(data:{mime_type};base64,{base64_data})"
        return match.group(0)
    css_content = re.sub(r'url\((.*?)\)', ReplaceUrl, css_content)
    return css_content

def FetchUrlsInParallel(session, url_list, http_timeout):
    results_map = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url_map = {executor.submit(FetchUrlContent, session, url, http_timeout): url for url in url_list}
        for completed_future in concurrent.futures.as_completed(future_to_url_map):
            url     = future_to_url_map[completed_future]
            content = completed_future.result()
            if content: results_map[url] = content
    return results_map

def InlineAllResources(state, session, target, html_content, http_timeout):
    html_content      = SanitizeXmlString(html_content)
    parser            = lxml.html.HTMLParser(recover=True)
    parsed_tree       = lxml.html.fromstring(html_content, parser=parser)
    all_resource_urls = set()
    script_elements   = parsed_tree.xpath("//script[@src]")
    css_link_elements = parsed_tree.xpath("//link[@rel='stylesheet'][@href]")
    image_elements    = parsed_tree.xpath("//img[@src]")
    media_elements    = parsed_tree.xpath("//source[@src]|//video[@src]|//audio[@src]")

    for element in script_elements:   all_resource_urls.add(urllib.parse.urljoin(target, element.attrib["src"]))
    for element in css_link_elements: all_resource_urls.add(urllib.parse.urljoin(target, element.attrib["href"]))
    for element in image_elements:    all_resource_urls.add(urllib.parse.urljoin(target, element.attrib["src"]))
    for element in media_elements:    all_resource_urls.add(urllib.parse.urljoin(target, element.attrib["src"]))

    fetched_resources_map = FetchUrlsInParallel(session, list(all_resource_urls), http_timeout)

    for element in script_elements:
        full_url = urllib.parse.urljoin(target, element.attrib["src"])
        if full_url in fetched_resources_map:
            element.attrib.pop("src", None)
            script_content = SanitizeXmlString(fetched_resources_map[full_url].decode("utf-8", "ignore"))
            if not script_content.strip(): continue
            element.text   = "\n" + script_content + "\n"
    Info(f"JavaScript inlined: {white}{len(script_elements)}")
    state["completed"] += 1

    for element in css_link_elements:
        full_url = urllib.parse.urljoin(target, element.attrib["href"])
        if full_url in fetched_resources_map:
            css_content         = fetched_resources_map[full_url].decode("utf-8", "ignore")
            css_content         = SanitizeXmlString(css_content)
            if not css_content.strip(): continue
            css_urls_in_content = re.findall(r'url\((.*?)\)', css_content)
            resource_sub_urls   = [urllib.parse.urljoin(full_url, url.strip('\'"')) for url in css_urls_in_content]
            extra_resources_map = FetchUrlsInParallel(session, resource_sub_urls, http_timeout)
            css_content         = InlineCssResourceUrls(full_url, css_content, extra_resources_map)
            style_element       = lxml.html.Element("style")
            style_element.text  = "\n" + css_content + "\n"
            element.getparent().replace(element, style_element)
    Info(f"Stylesheets inlined: {white}{len(css_link_elements)}")
    state["completed"] += 1

    for element in image_elements:
        full_url = urllib.parse.urljoin(target, element.attrib["src"])
        if full_url in fetched_resources_map:
            mime_type             = GetMimeTypeFromUrl(full_url)
            base64_data           = base64.b64encode(fetched_resources_map[full_url]).decode()
            element.attrib["src"] = f"data:{mime_type};base64,{base64_data}"
    Info(f"Images inlined: {white}{len(image_elements)}")
    state["completed"] += 1

    for element in media_elements:
        full_url = urllib.parse.urljoin(target, element.attrib["src"])
        if full_url in fetched_resources_map:
            mime_type             = GetMimeTypeFromUrl(full_url)
            base64_data           = base64.b64encode(fetched_resources_map[full_url]).decode()
            element.attrib["src"] = f"data:{mime_type};base64,{base64_data}"
    Info(f"Media inlined: {white}{len(media_elements)}")
    state["completed"] += 1

    raw_html = lxml.etree.tostring(parsed_tree, encoding="unicode", method="html")
    raw_html = SanitizeXmlString(raw_html)
    soup = bs4.BeautifulSoup(raw_html, "html.parser")
    structured_html = soup.prettify()
    return structured_html

def WebsiteCloner(target=None, http_timeout=None, http_proxy=None, useragent=None, cookie=None):
    Title("Website Cloner")

    if target is None:
        if not has_cli_args:
            target = Input("Target [-t] -> ")
        else:
            target = ""

    detect_target = DetectTarget(target)

    if detect_target not in ["url", "url/page", "domain", "domain/page", "localhost:port", "localhost:port/page", "ip:port", "ip:port/page"]: ErrorUrlDomainLocalhostportIpport()
    elif target and any(bad in target for bad in blacklists): ErrorTarget()

    default_http_timeout = 60

    if http_timeout is None:
        if not has_cli_args:
            http_timeout = Input(f"Max HTTP timeout [-HT] (default: {str(default_http_timeout)}) -> ")
        else:
            http_timeout = default_http_timeout

    if http_proxy is None:
        if not has_cli_args:
            http_proxy = Input(f"HTTP proxy [-HP] (default: {str(default_http_proxy)}) -> ")
        else:
            http_proxy = default_http_proxy

    if useragent is None:
        if not has_cli_args:
            useragent = Input(f"User-Agent [-u] (for random: random, default: {str(default_useragent)}) -> ")
        else:
            useragent = default_useragent

    if cookie is None:
        if not has_cli_args:
            cookie = Input(f"Cookie [-c] (default: {str(default_cookie)}) -> ")
        else:
            cookie = default_cookie

    if not http_proxy: http_proxy = default_http_proxy
    if not useragent : useragent  = default_useragent
    if not cookie    : cookie     = default_cookie

    try:
        if not http_timeout: http_timeout = default_http_timeout
        else: http_timeout = float(http_timeout)
        Info(f"Max HTTP timeout: {white}{str(http_timeout)}s")
    except (ValueError, TypeError): ErrorTimeout()

    session, proxies, cookie, useragent = EnableHttpProxyAndUserAgentAndCookie(http_proxy=http_proxy, useragent=useragent, cookie=cookie, http_timeout=http_timeout)

    Wait("Cloning..")

    state = {"stop": False, "completed": 0, "completed_total": 5}
    StartThread(StatsPressed, state, time_start=time.time())

    full_page_html, page_title = RenderFullPageWithRequests(state, session, target, http_timeout)

    if not full_page_html and not page_title:
        state["stop"] = True
        Continue()
        Reset()

    final_html_content = InlineAllResources(state, session, target, full_page_html, http_timeout)

    title = "".join(c if c.isalnum() or c in " _-" else "_" for c in page_title).strip()
    if not title: title = "page"
    output = f"{title}.html"

    with open(os.path.join(path_folder_ouput, output), "w", encoding="utf-8") as output_file:
        output_file.write(final_html_content)

    state["stop"] = True
    Info(f"Cloning completed: {white}{output}")

    interactive_mode = not has_cli_args and all(v is None for v in (target, http_timeout, http_proxy, useragent, cookie))
    if interactive_mode:
        Continue()
        Reset()