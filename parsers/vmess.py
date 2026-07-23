from tool import genName, b64Decode
import orjson
from urllib.parse import unquote

_HTTP_NETS = {'h2', 'http', 'tcp'}
_INVALID_SECURITY = {'http', 'gun', None, ''}

def _build_ws(path_raw, host, ed=None, eh=None):
    ws = {
        'type': 'ws',
        'path': path_raw,
        'headers': {
            'Host': host
        }
    }
    left, sep, right = path_raw.rpartition('?ed=')
    if sep and right.isdigit():
        ws['path'] = left
        ws['max_early_data'] = int(right)
    elif ed:
        ws['max_early_data'] = int(ed)
    if eh:
        ws['early_data_header_name'] = eh
    return ws

def parse(data):
    info = data[8:]

    if not info or info.isspace():
        return None

    try:
        if '?' in info:
            info_main, _, fragment = info.partition('#')
            netloc_and_path, _, query_str = info_main.partition('?')

            netquery = {}
            if query_str:
                start = 0
                end = len(query_str)
                netquery_set = netquery.__setitem__

                while start < end:
                    amp_idx = query_str.find('&', start)
                    if amp_idx == -1:
                        amp_idx = end

                    eq_idx = query_str.find('=', start, amp_idx)

                    if eq_idx != -1:
                        k = query_str[start:eq_idx]
                        v = query_str[eq_idx + 1:amp_idx]
                        if '%' in k or '+' in k:
                            k = unquote(k.replace('+', ' '))
                        if '%' in v or '+' in v:
                            v = unquote(v.replace('+', ' '))
                        netquery_set(k, v)

                    start = amp_idx + 1

            _p0, _, _p1 = netloc_and_path.partition('@')

            server, _, port_str = _p1.partition(':')
            server_port = int(port_str) if port_str.isdigit() else 443

            if ':' in _p0:
                security, _, uuid = _p0.partition(':')
            else:
                uuid = _p0
                security = 'auto'

            nq_get = netquery.get
            host = nq_get('host', '')
            path = nq_get('path', '/')
            ed = nq_get('ed')
            eh = nq_get('eh')

            tag_source = fragment
            if tag_source:
                tag = unquote(tag_source.replace('+', ' ')) if ('%' in tag_source or '+' in tag_source) else tag_source
            else:
                tag = genName() + '_vmess'

            node = {
                'tag': tag,
                'type': 'vmess',
                'server': server,
                'server_port': server_port,
                'uuid': uuid,
                'security': security,
                'alter_id': int(nq_get('alterId', '0')),
                'packet_encoding': 'xudp'
            }

            security_mode = nq_get('security')
            tls_enabled = nq_get('tls')
            
            if tls_enabled in ('1', 'true', 'True') or security_mode == 'tls':
                allow_insecure = nq_get('allowInsecure') == '1' or nq_get('insecure') == '1'
                tls = {
                    'enabled': True,
                    'insecure': allow_insecure,
                    'server_name': nq_get('sni', '')
                }
                fp = nq_get('fp')
                if fp:
                    tls['utls'] = {
                        'enabled': True,
                        'fingerprint': fp
                    }
                node['tls'] = tls

            if nq_get('obfs') == 'websocket' or nq_get('type') == 'ws':
                transport = _build_ws(
                    path,
                    host,
                    ed,
                    eh
                )

                node['transport'] = transport

                obfs_param = nq_get('obfsParam', '')
                if obfs_param and obfs_param[0] == '{':
                    try:
                        obfs_param_json = orjson.loads(obfs_param)
                        host_from_obfs_param = (
                            obfs_param_json.get('Host', '')
                        )
                        transport['headers']['Host'] = (
                            host_from_obfs_param or host
                        )
                    except orjson.JSONDecodeError:
                        pass

            return node

        proxy_str = b64Decode(info).decode('utf-8')

    except Exception as e:
        print(f"[vmess] Failed to parse: {e} | input: {info}")
        return None

    try:
        item = orjson.loads(proxy_str)
    except Exception:
        return None

    get = item.get

    ps = get('ps')
    content = ps.strip() if ps else genName() + '_vmess'
    scy = get('scy')
    security = 'auto' if scy in _INVALID_SECURITY else scy
    aid = get('aid')
    alter_id = int(aid) if aid is not None else 0
    node = {
        'tag': content,
        'type': 'vmess',
        'server': get('add'),
        'server_port': int(get('port')),
        'uuid': get('id'),
        'security': security,
        'alter_id': alter_id,
        'packet_encoding': 'xudp'
    }

    net_val = get('net')
    tls_val = get('tls')

    if tls_val not in (None, '', 'none'):
        tls = {
            'enabled': True,
            'insecure': True,
            'server_name': (
                get('host', '')
                if net_val not in ('h2', 'http')
                else ''
            )
        }

        if get('verify_cert') is False:
            tls['insecure'] = False
        sni = get('sni')
        if sni:
            tls['server_name'] = sni
        fp = get('fp')
        if fp:
            tls['utls'] = {
                'enabled': True,
                'fingerprint': fp
            }

        node['tls'] = tls

    if net_val:
        if net_val in _HTTP_NETS:
            transport = {
                'type': 'http'
            }
            headers = get('headers')
            if headers:
                transport['headers'] = headers
            host = get('host')
            if host:
                transport['host'] = host
            path_field = get('path')
            if path_field:
                if isinstance(path_field, str):
                    transport['path'] = path_field.split('?', 1)[0]
                else:
                    transport['method'] = 'GET'
                    transport['path'] = path_field[0]
            node['transport'] = transport
        elif net_val == 'ws':
            node['transport'] = _build_ws(
                get('path', '/'),
                get('host', ''),
                get('ed'),
                get('eh')
            )
        elif net_val == 'quic':
            node['transport'] = {
                'type': 'quic'
            }
        elif net_val == 'grpc':
            node['transport'] = {
                'type': 'grpc',
                'service_name': get('path', '')
            }

    return node