from tool import genName
from urllib.parse import unquote

def parse(data: str) -> dict:
    main_part_full, _, fragment = data.partition('#')

    at_idx = main_part_full.find('@', 8)
    if at_idx == -1:
        return None

    uuid = main_part_full[8:at_idx].split(':')[-1]
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
                params_set(
                    query_str[start:eq_idx],
                    query_str[eq_idx + 1:amp_idx]
                )

            start = amp_idx + 1

    get = params.get

    path_raw = get('path', '/')
    if '%' in path_raw:
        path_raw = unquote(path_raw)

    tag_source = fragment

    if tag_source:
        tag = unquote(tag_source) if '%' in tag_source else tag_source
    else:
        tag = genName() + '_vless'

    security = get('security', '').lower()
    transport_type = get('type')

    node = {
        'tag': tag,
        'type': 'vless',
        'server': server,
        'server_port': server_port,
        'uuid': uuid,
        'packet_encoding': get('packetEncoding', 'xudp')
    }

    flow = get('flow')
    if flow:
        node['flow'] = flow

    sni = get('sni') or get('peer') or ''
    allow_insecure = get('allowInsecure') == '1'
    alpn = get('alpn')
    fp = get('fp')
    pbk = get('pbk')

    if security not in ('none', '') or get('tls') == '1':
        tls_config = {
            'enabled': True,
            'insecure': allow_insecure,
            'server_name': '' if sni == 'None' else sni
        }

        if alpn:
            alpn_items = []

            for item in alpn.strip('{}').split(','):
                item = item.strip()

                if not item:
                    continue

                if '%' in item:
                    item = unquote(item)

                alpn_items.append(item)

            if alpn_items:
                tls_config['alpn'] = alpn_items

        if fp:
            tls_config['utls'] = {
                'enabled': True,
                'fingerprint': fp
            }

        if security == 'reality' or pbk:
            reality = {
                'enabled': True,
                'public_key': pbk
            }

            sid = get('sid')

            if sid and sid.lower() != 'none':
                reality['short_id'] = sid

            tls_config['reality'] = reality

            if 'utls' not in tls_config:
                tls_config['utls'] = {
                    'enabled': True
                }

        node['tls'] = tls_config

    if transport_type == 'ws' or get('obfs') == 'websocket':
        if transport_type == 'ws':
            ws_host = get('host') or get('sni') or ''
        else:
            ws_host = get('peer') or get('obfsParam') or ''
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
        tls = node.get('tls')
        if tls and not tls['server_name']:
            tls['server_name'] = ws_host

    elif transport_type == 'grpc':
        service_name = get('serviceName', '')
        if '%' in service_name:
            service_name = unquote(service_name)
        node['transport'] = {
            'type': 'grpc',
            'service_name': service_name
        }

    elif transport_type == 'http':
        node['transport'] = {
            'type': 'http',
            'path': path_raw
        }

    return node