from tool import genName, b64Decode
from urllib.parse import unquote, unquote_plus

def split_unescaped(s, delim, maxsplit=-1):
    parts = []
    start = 0
    search_start = 0
    delim_len = len(delim)

    while maxsplit != 0:
        idx = s.find(delim, search_start)
        if idx == -1:
            break
        if idx > 0 and s[idx-1] == '\\':
            search_start = idx + delim_len
        else:
            parts.append(s[start:idx])
            start = idx + delim_len
            search_start = start
            maxsplit -= 1

    parts.append(s[start:])
    return parts

def unescape_char(s):
    if '\\' not in s:
        return s

    res = []
    i = 0
    length = len(s)

    while i < length:
        c = s[i]
        if c == '\\' and i + 1 < length:
            res.append(s[i+1])
            i += 2
        else:
            res.append(c)
            i += 1

    return ''.join(res)

def _try_b64url_decode(b64func, s):
    if not s:
        return None
    pad = (-len(s)) % 4
    s_padded = s + ('=' * pad)
    try:
        decoded = b64func(s_padded)
    except Exception:
        return None
    if not isinstance(decoded, (bytes, bytearray)):
        return None
    try:
        txt = decoded.decode('utf-8', errors='strict')
    except Exception:
        return None
    return txt if ':' in txt else None

def _parse_plugin_options(raw):
    if not raw:
        return None, {}

    tokens = split_unescaped(raw, ';')
    if not tokens:
        return None, {}

    plugin_name = unescape_char(tokens[0])
    opts = {}

    for token in tokens[1:]:
        if not token:
            continue
        parts = split_unescaped(token, '=', maxsplit=1)
        key = unescape_char(parts[0]).strip()
        if key:
            val = unescape_char(parts[1]) if len(parts) > 1 else ''
            opts[key] = val

    return plugin_name, opts

def parse(data):
    if not data or not data.startswith('ss://') or len(data) <= 5:
        return None

    tail = data[5:]
    tag = None

    if '#' in tail:
        tail, _, frag = tail.partition('#')
        if frag:
            tag = unquote_plus(frag)

    query = ''
    if '?' in tail:
        tail, _, query = tail.partition('?')

    node = {
        'tag': tag,
        'type': 'shadowsocks',
        'server': None,
        'server_port': 0,
        'method': None,
        'password': None,
    }

    plugin_raw = None
    if query:
        for part in query.split('&'):
            if part.startswith('plugin='):
                plugin_raw = unquote(part[7:])
                break

    if plugin_raw:
        plugin_name, plugin_opts = _parse_plugin_options(plugin_raw)
        if plugin_name:
            node['plugin'] = plugin_name
            if plugin_opts:
                parts = [f"{k}={v}" if v != '' else k for k, v in plugin_opts.items()]
                node['plugin_opts'] = ';'.join(parts)
            else:
                node['plugin_opts'] = ''

    if tail.endswith('/'):
        tail = tail[:-1]

    cred_end = tail.find('@')
    if cred_end == -1:
        return None

    credentials = tail[:cred_end]
    rest = tail[cred_end + 1:]

    host_end = rest.rfind(':')
    if host_end == -1:
        return None

    host = rest[:host_end]
    port_str = rest[host_end + 1:]

    if port_str.endswith('\n'):
        port_str = port_str[:-1]

    if not host or not port_str.isdigit():
        return None

    node['server'] = host[1:-1] if host.startswith('[') and host.endswith(']') else host
    node['server_port'] = port_str

    decoded_cred = _try_b64url_decode(b64Decode, credentials)
    if decoded_cred:
        parts = decoded_cred.split(':', 1)
        if len(parts) != 2:
            return None
        node['method'], node['password'] = parts
    else:
        if ':' in credentials:
            parts = credentials.split(':', 1)
            if len(parts) != 2:
                return None
            node['method'] = unquote(parts[0])
            node['password'] = unquote(parts[1])
        else:
            dec = unquote(credentials)
            parts = dec.split(':', 1)
            if len(parts) != 2:
                return None
            node['method'], node['password'] = parts

    try:
        node['server_port'] = int(node['server_port'])
    except Exception:
        node['server_port'] = 0

    if node.get('tag') is None:
        node['tag'] = genName() + '_shadowsocks'

    return node