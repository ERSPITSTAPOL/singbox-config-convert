from tool import genName
from urllib.parse import unquote

def parse(data: str) -> dict:
    main_part_full, _, fragment = data.partition('#')

    if main_part_full.startswith('https://'):
        is_https = True
        start_idx = 8
    elif main_part_full.startswith('http://'):
        is_https = False
        start_idx = 7
    else:
        return None

    rest_part = main_part_full[start_idx:]
    netloc_and_path, _, query_str = rest_part.partition('?')
    hp_part, _, _ = netloc_and_path.partition('/')

    if '@' not in hp_part:
        return None

    user_pass, _, server_port_str = hp_part.rpartition('@')
    username, _, password = user_pass.partition(':')

    if server_port_str.startswith('['):
        r_idx = server_port_str.rfind(']')
        server = server_port_str[1:r_idx]
        p_part = server_port_str[r_idx + 1:]
        server_port = int(p_part[1:]) if p_part.startswith(':') else (443 if is_https else 80)
    else:
        r_idx = server_port_str.rfind(':')
        if r_idx != -1:
            p_str = server_port_str[r_idx + 1:]
            if p_str.isdigit():
                server = server_port_str[:r_idx]
                server_port = int(p_str)
            else:
                server = server_port_str
                server_port = 443 if is_https else 80
        else:
            server = server_port_str
            server_port = 443 if is_https else 80

    params = {}
    if query_str:
        for pair in query_str.split('&'):
            if pair:
                k, _, v = pair.partition('=')
                params[k] = v

    get = params.get

    remarks = get('remarks')
    if remarks:
        tag = unquote(remarks)
    elif fragment:
        tag = unquote(fragment) if '%' in fragment else fragment
    else:
        tag = genName() + '_http'

    node = {
        'tag': tag,
        'type': 'http',
        'server': server,
        'server_port': server_port,
        'username': unquote(username),
        'password': unquote(password)
    }

    security = get('security', '').lower()
    has_tls = is_https or get('sni') or get('tls') == '1' or security not in ('none', '')

    if has_tls:
        tls_config = {
            'enabled': True,
            'insecure': get('allowInsecure') == '1'
        }
        if (sni := get('sni') or get('peer')) and sni != 'None':
            tls_config['server_name'] = sni
        if (alpn := get('alpn')):
            tls_config['alpn'] = [
                unquote(alpn_entry.strip())
                for alpn_entry in alpn.strip('{}').split(',')
                if alpn_entry
            ]
        if (fp := get('fp')):
            tls_config['utls'] = {
                'enabled': True,
                'fingerprint': fp
            }
        if security == 'reality' or get('pbk'):
            reality = {
                'enabled': True,
                'public_key': get('pbk')
            }
            sid = get('sid')
            if sid and sid.lower() != 'none':
                reality['short_id'] = sid
            tls_config['reality'] = reality
            if 'utls' not in tls_config:
                tls_config['utls'] = {'enabled': True}
        node['tls'] = tls_config

    return node