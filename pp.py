from flask import Flask, request, Response, send_file, after_this_request
import requests
from urllib.parse import urljoin, urlparse, urlencode
import re
import logging
from bs4 import BeautifulSoup
import chardet
import urllib3
import tempfile
import os
import threading
import time

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEBUG_MODE = False
PROXY_PREFIX = '/proxy/'

# 禁用不安全请求警告（如果禁用 SSL 验证）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 定义文件大小限制为 20MB
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB in bytes

# 存储下载的文件路径和创建时间，用于定期清理
downloaded_files = {}

def fix_headers(headers):
    """清理并修复 HTTP 头部。"""
    excluded_headers = [
        'content-encoding', 'content-length', 'transfer-encoding', 'connection',
        'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers',
        'upgrade', 'host', 'origin', 'referer', 'if-modified-since', 'if-none-match',
        'accept-encoding', 'cache-control', 'pragma', 'cross-origin-opener-policy',
        'cross-origin-embedder-policy', 'cross-origin-resource-policy', 'content-security-policy'
    ]
    headers_dict = {k: v for k, v in headers.items()
                    if k.lower() not in excluded_headers}
    # 添加 CORS 头部
    headers_dict.update({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Allow-Credentials': 'true'
    })
    return headers_dict

def detect_encoding(content):
    """检测内容的编码。"""
    if not content:
        return 'utf-8'
    result = chardet.detect(content)
    return result['encoding'] if result['encoding'] else 'utf-8'

def extract_charset(content_type):
    """从 Content-Type 头部提取字符集。"""
    match = re.search(r'charset=([^\s;]+)', content_type, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def rewrite_urls(content, base_url, content_type, encoding='utf-8'):
    """重写内容中的 URL。"""
    if not content:
        return content

    try:
        # 使用指定编码解码内容
        decoded_content = content.decode(encoding, errors='ignore')

        # 处理 HTML 内容
        if 'text/html' in content_type:
            soup = BeautifulSoup(decoded_content, 'html.parser')

            # 移除可能存在的 CSP 元标签
            for meta in soup.find_all('meta', {'http-equiv': 'Content-Security-Policy'}):
                meta.decompose()

            # 注入 Service Worker 脚本
            if soup.head:
                sw_registration_script = soup.new_tag('script')
                sw_registration_script.string = '''
                if ('serviceWorker' in navigator) {
                    navigator.serviceWorker.register('/proxy/sw.js', {scope: '/'})
                    .then(registration => {
                        registration.addEventListener('activate', event => {
                            event.waitUntil(clients.claim());
                        });
                    }).catch(console.error);
                }
                '''
                soup.head.insert(0, sw_registration_script)

            # 注入 URL 重写脚本，使用外部文件避免 CSP 问题
            if soup.body:
                rewrite_script_tag = soup.new_tag('script', src='/proxy/rewrite.js')
                soup.body.append(rewrite_script_tag)

            # 重写静态 URL
            for tag in soup.find_all(True):
                for attr in ['src', 'href', 'action', 'data-src', 'data-href']:
                    if tag.has_attr(attr):
                        url = tag[attr]
                        if url and not url.startswith((
                            'data:', 'javascript:', 'about:', 'blob:', '#'
                        )):
                            absolute_url = urljoin(base_url, url)
                            if not absolute_url.startswith(PROXY_PREFIX):
                                tag[attr] = f"{PROXY_PREFIX}{absolute_url}"

            return str(soup).encode('utf-8')

        # 处理 CSS 内容
        elif 'text/css' in content_type:
            # 重写 CSS 中的 URL
            url_pattern = r'url\([\'"]?((?!data:)[^\'"\)]+)[\'"]?\)'
            def replace_css_url(match):
                url = match.group(1)
                if not url.startswith((
                    'data:', 'javascript:', 'about:', 'blob:', '#'
                )):
                    absolute_url = urljoin(base_url, url)
                    return f'url({PROXY_PREFIX}{absolute_url})'
                return f'url({url})'
            processed_content = re.sub(url_pattern, replace_css_url, decoded_content)
            return processed_content.encode('utf-8')

        # 处理 JavaScript 内容
        elif 'javascript' in content_type:
            # 重写 JS 代码中的 URL
            js_url_pattern = r'([\'"])(https?://[^\'"]+)\1'
            def replace_js_url(match):
                quote = match.group(1)
                url = match.group(2)
                if should_proxy_url(url):
                    return f'{quote}{PROXY_PREFIX}{url}{quote}'
                return match.group(0)
            processed_content = re.sub(js_url_pattern, replace_js_url, decoded_content)
            return processed_content.encode('utf-8')

    except Exception as e:
        logger.error(f"Error rewriting URLs: {str(e)}")
        return content

    return content

def should_proxy_url(url):
    """判断一个 URL 是否需要被代理。"""
    if not url:
        return False
    return not url.startswith((
        PROXY_PREFIX, 'data:', 'javascript:', 'about:', 'blob:', '#'
    ))

# Service Worker 脚本
SERVICE_WORKER_SCRIPT = '''
self.addEventListener('install', event => {
    event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // 忽略已经被代理的请求或特殊协议的请求
    if (!url.pathname.startsWith('/proxy/') && !url.protocol.startsWith('data:') && !url.protocol.startsWith('blob:')) {
        const proxiedUrl = self.location.origin + '/proxy/' + url.href;
        event.respondWith(
            fetch(proxiedUrl, {
                method: event.request.method,
                headers: event.request.headers,
                body: event.request.body,
                mode: 'cors',
                credentials: 'include',
                redirect: 'manual'
            }).then(response => {
                if (response.status >= 300 && response.status < 400) {
                    const location = response.headers.get('Location');
                    if (location) {
                        const absoluteLocation = new URL(location, url.href).href;
                        return fetch(self.location.origin + '/proxy/' + absoluteLocation, {
                            method: event.request.method,
                            headers: event.request.headers,
                            body: event.request.body,
                            mode: 'cors',
                            credentials: 'include',
                            redirect: 'manual'
                        });
                    }
                }
                return response;
            })
        );
    }
});
'''

# URL 重写脚本
URL_REWRITE_SCRIPT = '''
(function() {
    const proxyPrefix = window.location.origin + '/proxy/';

    // 判断是否需要代理 URL
    function shouldProxyUrl(url) {
        return url &&
               !url.startsWith(proxyPrefix) &&
               !url.startsWith('data:') &&
               !url.startsWith('javascript:') &&
               !url.startsWith('about:') &&
               !url.startsWith('blob:') &&
               !url.startsWith('#');
    }

    // 获取被代理的 URL
    function getProxiedUrl(url) {
        if (!shouldProxyUrl(url)) return url;
        try {
            const absoluteUrl = new URL(url, window.location.href).href;
            return proxyPrefix + absoluteUrl;
        } catch (e) {
            return url;
        }
    }

    // 拦截 XMLHttpRequest
    const originalXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...args) {
        const proxiedUrl = getProxiedUrl(url);
        originalXHROpen.call(this, method, proxiedUrl, ...args);
    };

    // 拦截 Fetch API
    const originalFetch = window.fetch;
    window.fetch = function(resource, init) {
        if (typeof resource === 'string') {
            resource = getProxiedUrl(resource);
        } else if (resource instanceof Request) {
            resource = new Request(getProxiedUrl(resource.url), resource);
        }
        return originalFetch(resource, init);
    };

    // 拦截动态创建的元素
    const originalCreateElement = document.createElement;
    document.createElement = function(tagName, options) {
        const element = originalCreateElement.call(document, tagName, options);
        // 重写元素的 setAttribute 方法
        const originalSetAttribute = element.setAttribute;
        element.setAttribute = function(name, value) {
            if (['src', 'href', 'action', 'data-src', 'data-href'].includes(name)) {
                value = getProxiedUrl(value);
            }
            originalSetAttribute.call(this, name, value);
        };
        return element;
    };

    // 重写表单提交
    document.addEventListener('submit', function(e) {
        const form = e.target;
        if (form.tagName === 'FORM') {
            const action = form.action;
            if (shouldProxyUrl(action)) {
                form.action = getProxiedUrl(action);
            }
        }
    }, true);

    // 拦截 History API
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;

    history.pushState = function(state, title, url) {
        if (url) {
            url = getProxiedUrl(url);
        }
        return originalPushState.call(this, state, title, url);
    };

    history.replaceState = function(state, title, url) {
        if (url) {
            url = getProxiedUrl(url);
        }
        return originalReplaceState.call(this, state, title, url);
    };

    // 观察 DOM 变化以重写 URL
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            mutation.addedNodes.forEach((node) => {
                if (node.nodeType === 1) {  // 元素节点
                    rewriteElementUrls(node);
                }
            });
        });
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true
    });

    function rewriteElementUrls(element) {
        const urlAttributes = ['src', 'href', 'action', 'data-src', 'data-href'];
        urlAttributes.forEach(attr => {
            if (element.hasAttribute && element.hasAttribute(attr)) {
                const originalUrl = element.getAttribute(attr);
                if (shouldProxyUrl(originalUrl)) {
                    try {
                        element.setAttribute(attr, getProxiedUrl(originalUrl));
                    } catch (e) {
                        // 忽略无效的 URL
                    }
                }
            }
        });

        // 观察属性变化
        const elementObserver = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'attributes' && urlAttributes.includes(mutation.attributeName)) {
                    const attr = mutation.attributeName;
                    const originalUrl = element.getAttribute(attr);
                    if (shouldProxyUrl(originalUrl)) {
                        element.setAttribute(attr, getProxiedUrl(originalUrl));
                    }
                }
            });
        });

        elementObserver.observe(element, {
            attributes: true
        });

        // 递归重写子元素
        if (element.children) {
            Array.from(element.children).forEach(child => {
                rewriteElementUrls(child);
            });
        }
    }

    // 初始重写文档中所有的 URL
    document.querySelectorAll('*').forEach(rewriteElementUrls);

    // 拦截 window.open
    const originalWindowOpen = window.open;
    window.open = function(url, name, specs, replace) {
        return originalWindowOpen.call(window, getProxiedUrl(url), name, specs, replace);
    };

    // 拦截直接赋值给 src 和 href
    ['HTMLImageElement', 'HTMLScriptElement', 'HTMLLinkElement', 'HTMLAnchorElement', 'HTMLIFrameElement'].forEach(tag => {
        const prototype = window[tag] && window[tag].prototype;
        if (prototype && prototype.hasOwnProperty('src')) {
            const originalSrcDescriptor = Object.getOwnPropertyDescriptor(prototype, 'src');
            Object.defineProperty(prototype, 'src', {
                get: function() {
                    return originalSrcDescriptor.get.call(this);
                },
                set: function(value) {
                    originalSrcDescriptor.set.call(this, getProxiedUrl(value));
                }
            });
        }
        if (prototype && prototype.hasOwnProperty('href')) {
            const originalHrefDescriptor = Object.getOwnPropertyDescriptor(prototype, 'href');
            Object.defineProperty(prototype, 'href', {
                get: function() {
                    return originalHrefDescriptor.get.call(this);
                },
                set: function(value) {
                    originalHrefDescriptor.set.call(this, getProxiedUrl(value));
                }
            });
        }
    });

    // 拦截 CSSStyleSheet 的 insertRule 和 addRule
    const originalInsertRule = CSSStyleSheet.prototype.insertRule;
    CSSStyleSheet.prototype.insertRule = function(rule, index) {
        rule = rewriteCssUrls(rule);
        return originalInsertRule.call(this, rule, index);
    };

    const originalAddRule = CSSStyleSheet.prototype.addRule;
    CSSStyleSheet.prototype.addRule = function(selector, style, index) {
        style = rewriteCssUrls(style);
        return originalAddRule.call(this, selector, style, index);
    };

    function rewriteCssUrls(cssText) {
        const urlPattern = /url\\(['"]?([^'"]+?)['"]?\\)/g;
        return cssText.replace(urlPattern, function(match, p1) {
            if (shouldProxyUrl(p1)) {
                return 'url(' + getProxiedUrl(p1) + ')';
            }
            return match;
        });
    }

})();
'''

@app.route('/proxy/sw.js')
def service_worker():
    """提供 Service Worker 脚本。"""
    response = Response(SERVICE_WORKER_SCRIPT,
                        mimetype='application/javascript')
    # 移除 CSP 头部
    response.headers.pop('Content-Security-Policy', None)
    return response

@app.route('/proxy/rewrite.js')
def rewrite_js():
    """提供 URL 重写脚本。"""
    response = Response(URL_REWRITE_SCRIPT,
                        mimetype='application/javascript')
    # 移除 CSP 头部
    response.headers.pop('Content-Security-Policy', None)
    return response

def schedule_file_deletion(file_path, delay=3600):
    """在指定时间后删除文件。"""
    def delete_file():
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Deleted file: {file_path}")
        except Exception as e:
            logger.error(f"Error deleting file {file_path}: {str(e)}")
    timer = threading.Timer(delay, delete_file)
    timer.start()

def cleanup_old_files():
    """定期清理超过 1 小时的文件。"""
    while True:
        current_time = time.time()
        files_to_delete = []
        for file_path, create_time in list(downloaded_files.items()):
            if current_time - create_time > 3600:  # 1 hour
                files_to_delete.append(file_path)
        for file_path in files_to_delete:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Deleted old file: {file_path}")
                downloaded_files.pop(file_path, None)
            except Exception as e:
                logger.error(f"Error deleting file {file_path}: {str(e)}")
        time.sleep(600)  # 每 10 分钟检查一次

# 启动文件清理线程
cleanup_thread = threading.Thread(target=cleanup_old_files, daemon=True)
cleanup_thread.start()

@app.route('/proxy/<path:url>', methods=[
    'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'
])
def proxy(url):
    try:
        # 构建完整的目标 URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # 获取原始请求信息
        method = request.method
        headers = dict(request.headers)
        params = request.args
        data = request.get_data()

        # 移除或修改请求头
        excluded_request_headers = [
            'Host', 'Origin', 'Referer', 'Accept-Encoding',
            'If-Modified-Since', 'If-None-Match', 'Cache-Control', 'Pragma'
        ]
        for h in excluded_request_headers:
            headers.pop(h, None)
        headers['X-Forwarded-For'] = request.remote_addr

        # 发送请求到目标服务器
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data,
            cookies=request.cookies,
            stream=True,  # 对于下载请求，需要流式传输
            verify=False,   # 根据需要启用或禁用 SSL 证书验证
            allow_redirects=False  # 禁用自动重定向
        )

        # 处理重定向响应
        if response.status_code in [301, 302, 303, 307, 308]:
            redirect_url = response.headers.get('Location', '')
            if redirect_url:
                # 处理相对 URL
                absolute_redirect_url = urljoin(url, redirect_url)
                proxied_redirect_url = f'/proxy/{absolute_redirect_url}'
                headers = fix_headers(dict(response.headers))
                headers['Location'] = proxied_redirect_url

                # 返回重定向响应
                return Response('',
                                status=response.status_code,
                                headers=headers)

        # 获取响应内容和类型
        content_type = response.headers.get('content-type', '')

        # 从 Content-Type 中提取字符集
        charset = extract_charset(content_type)
        if not charset:
            # 如果未指定字符集，则设置为 utf-8
            charset = 'utf-8'

        # 检测是否为下载请求
        content_disposition = response.headers.get('content-disposition', '')
        is_attachment = 'attachment' in content_disposition.lower()

        # 如果是下载请求，下载文件到临时目录，然后返回给前端
        if is_attachment:
            temp_dir = tempfile.mkdtemp()
            file_name = re.findall('filename="?([^\'";]+)"?', content_disposition)
            if file_name:
                file_name = file_name[0]
            else:
                # 如果未提供文件名，生成一个唯一的文件名
                file_name = 'downloaded_file'
            file_path = os.path.join(temp_dir, file_name)

            total_size = 0
            chunk_size = 8192  # 8KB

            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        total_size += len(chunk)
                        if total_size > MAX_FILE_SIZE:
                            # 超过文件大小限制，停止下载并删除文件
                            f.close()
                            os.remove(file_path)
                            logger.warning(f"File size exceeds {MAX_FILE_SIZE} bytes. Download aborted.")
                            return Response(f'File size exceeds {MAX_FILE_SIZE} bytes.', status=413)
                        f.write(chunk)

            # 记录下载的文件和创建时间
            downloaded_files[file_path] = time.time()

            # 安排文件在 1 小时后删除
            schedule_file_deletion(file_path, delay=3600)

            # 将文件返回给前端
            @after_this_request
            def remove_temp_dir(response):
                try:
                    if os.path.exists(temp_dir):
                        os.rmdir(temp_dir)
                except Exception as e:
                    logger.error(f"Error removing temp dir {temp_dir}: {str(e)}")
                return response

            return send_file(
                file_path,
                as_attachment=True,
                attachment_filename=file_name,
                mimetype=content_type
            )

        else:
            # 读取内容，限制最大读取大小，防止内存过大
            content = response.content

            # 重写响应内容中的 URL
            if content:
                modified_content = rewrite_urls(content, url, content_type, encoding=charset)
            else:
                modified_content = content

            # 处理响应头
            response_headers = fix_headers(dict(response.headers))

            # 更新 Content-Type，确保 charset 为 utf-8
            if content_type:
                content_type = f"{content_type.split(';')[0]}; charset=utf-8"
                response_headers['Content-Type'] = content_type

            # 处理 cookies
            if 'Set-Cookie' in response_headers:
                cookies = response_headers.pop('Set-Cookie')
                # 根据需要修改 Cookie 的域或路径
                response_headers['Set-Cookie'] = cookies

            # 移除 CSP 头部
            response_headers.pop('Content-Security-Policy', None)

            return Response(
                modified_content,
                status=response.status_code,
                headers=response_headers
            )

    except Exception as e:
        logger.error(f"Proxy error: {str(e)}")
        return Response(f'Proxy Error: {str(e)}', status=500)

def main():
    app.run(host='0.0.0.0', port=1027, debug=DEBUG_MODE)

if __name__ == '__main__':
    main()
