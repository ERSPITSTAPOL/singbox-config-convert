from tool import genName
from urllib.parse import unquote

def parse(data: str) -> dict:
    scheme_idx = data.find('://')
    start_pos = scheme_idx + 3 if scheme_idx != -1 else 0

    hash_idx = data.find('#', start_pos)
    if hash_idx != -1:
        main_part = data[start_pos:hash_idx]
        fragment = data[hash_idx + 1:]
    else:
        main_part = data[start_pos:]
        fragment = ""

    q_idx = main_part.find('?')
    if q_idx != -1:
        netloc_and_path = main_part[:q_idx]
        query_str = main_part[q_idx + 1:]
    else:
        netloc_and_path = main_part
        query_str = ""

    slash_idx = netloc_and_path.find('/')
    if slash_idx != -1:
        netloc = netloc_and_path[:slash_idx]
    else:
        netloc = netloc_and_path

    at_idx = netloc.rfind('@')
    if at_idx != -1:
        userinfo = netloc[:at_idx]
        host_port = netloc[at_idx + 1:]
        colon_user_idx = userinfo.rfind(':')
        if colon_user_idx != -1:
            pw_from_netloc = userinfo[colon_user_idx + 1:]
        else:
            pw_from_netloc = userinfo
    else:
        host_port = netloc
        pw_from_netloc = ""

    if host_port.startswith('['):
        end_bracket = host_port.find(']')
        server = host_port[1:end_bracket]
        raw_port_part = host_port[end_bracket + 1:]
        if raw_port_part.startswith(':'):
            raw_port = raw_port_part[1:]
        else:
            raw_port = ""
    else:
        r_colon_idx = host_port.rfind(':')
        if r_colon_idx != -1:
            server = host_port[:r_colon_idx]
            raw_port = host_port[r_colon_idx + 1:]
        else:
            server = host_port
            raw_port = ""

    if raw_port:
        comma_idx = raw_port.find(',')
        if comma_idx != -1:
            raw_port = raw_port[:comma_idx]
        server_port = int(raw_port)
    else:
        server_port = 443

    params = {}
    if query_str:
        start = 0
        end = len(query_str)
        params_set = params.__setitem__

        while start < end:
            amp_idx = query_str.find('&', start)
            if amp_idx == -1:
                amp_idx = end

            eq_idx = query_str.find('=', start, amp_idx)
            if eq_idx != -1:
                k = query_str[start:eq_idx]
                v = query_str[eq_idx + 1:amp_idx]
                if '%' in v:
                    v = unquote(v)
                params_set(k, v)

            start = amp_idx + 1

    get = params.get

    auth = get('auth')
    if auth:
        password = auth 
    else:
        password = unquote(pw_from_netloc) if '%' in pw_from_netloc else pw_from_netloc

    sni = get('sni')
    if sni is None:
        sni = get('peer')
    sni = sni if sni is not None else ''

    if fragment:
        tag = unquote(fragment) if '%' in fragment else fragment
    else:
        tag = genName() + '_anytls'

    node = {
        'tag': tag,
        'type': 'anytls',
        'server': server,
        'server_port': server_port,
        'password': password,
        'tls': {
            'enabled': True,
            'server_name': sni,
            'insecure': False
        }
    }

    if (check_int := get('idleSessionCheckInterval')):
        node['idle_session_check_interval'] = check_int + 's'
    if (timeout := get('idleSessionTimeout')):
        node['idle_session_timeout'] = timeout + 's'
    if (min_idle := get('minIdleSession')):
        node['min_idle_session'] = int(min_idle)
    if (fp := get('fp')):
        node['tls']['utls'] = {
            'enabled': True,
            'fingerprint': fp
        }
    if (alpn := get('alpn')):
        node['tls']['alpn'] = alpn.strip('{}').split(',')
    if get('insecure') == '1' or get('allowInsecure') == '1':
        node['tls']['insecure'] = True

    return node