from tool import genName
from urllib.parse import unquote

def parse(data: str) -> dict:
    main_part_full, _, fragment = data.partition('#')

    at_idx = main_part_full.find('@', 9)
    if at_idx == -1:
        return None

    password = unquote(main_part_full[9:at_idx])
    rest = main_part_full[at_idx + 1:]

    netloc_and_path, _, query_str = rest.partition('?')
    hp_part, _, _ = netloc_and_path.partition('/')

    if hp_part.startswith('['):
        r_idx = hp_part.rfind(']')

        server = hp_part[1:r_idx]

        p_part = hp_part[r_idx + 1:]
        server_port = int(p_part[1:]) if p_part.startswith(':') else 443

    else:
        r_idx = hp_part.rfind(':')

        if r_idx != -1:
            p_str = hp_part[r_idx + 1:]

            if p_str.isdigit():
                server = hp_part[:r_idx]
                server_port = int(p_str)
            else:
                server = hp_part
                server_port = 443
        else:
            server = hp_part
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

                if '%' in k:
                    k = unquote(k)

                if '%' in v:
                    v = unquote(v)

                params_set(k, v)

            start = amp_idx + 1

    get = params.get

    tag_source = fragment

    if tag_source:
        tag = unquote(tag_source) if '%' in tag_source else tag_source
    else:
        tag = genName() + '_trojan'

    node = {
        'tag': tag,
        'type': 'trojan',
        'server': server,
        'server_port': server_port,
        'password': password,
        'tls': {
            'enabled': True,
            'insecure': False
        }
    }

    tls = node['tls']

    if get('allowInsecure') == '1':
        tls['insecure'] = True

    alpn = get('alpn')

    if alpn:
        alpn_list = []

        for item in alpn.strip('{}').split(','):
            item = item.strip()

            if item:
                alpn_list.append(item)

        if alpn_list:
            tls['alpn'] = alpn_list

    sni = get('sni') or get('peer') or ''

    if sni and sni != 'None':
        tls['server_name'] = sni

    fp = get('fp')

    if fp:
        tls['utls'] = {
            'enabled': True,
            'fingerprint': fp
        }

    pbk = get('pbk')
    security = get('security', '').lower()

    if security == 'reality' or pbk:
        reality = {
            'enabled': True,
            'public_key': pbk
        }

        sid = get('sid')

        if sid and sid.lower() != 'none':
            reality['short_id'] = sid

        tls['reality'] = reality

        if 'utls' not in tls:
            tls['utls'] = {
                'enabled': True
            }

    t_type = get('type')

    if t_type:

        if t_type == 'h2':
            path = get('path', '/')
            if '%' in path:
                path = unquote(path)
            node['transport'] = {
                'type': 'http',
                'host': get('host', server),
                'path': path
            }

        elif t_type == 'ws':
            ws_host = get('host') or sni
            path_raw = get('path', '/')
            if '%' in path_raw:
                path_raw = unquote(path_raw)
            ed = get('ed')
            eh = get('eh')
            ws_config = {
                'type': 'ws',
                'path': path_raw,
                'headers': {
                    'Host': ws_host
                }
            }
            left, sep, right = path_raw.rpartition('?ed=')
            if sep and right.isdigit():
                ws_config['path'] = left
                ws_config['max_early_data'] = int(right)
            elif ed:
                ws_config['max_early_data'] = int(ed)
            if eh:
                ws_config['early_data_header_name'] = eh
            node['transport'] = ws_config
            if not tls.get('server_name') and ws_host:
                tls['server_name'] = ws_host

        elif t_type == 'grpc':
            service_name = get('serviceName', '')
            if '%' in service_name:
                service_name = unquote(service_name)
            node['transport'] = {
                'type': 'grpc',
                'service_name': service_name
            }

    return node