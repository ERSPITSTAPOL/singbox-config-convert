from tool import genName
from urllib.parse import unquote

_TRUE_STRINGS = frozenset(('1', 'true'))

def parse(data: str) -> dict:
    sep_idx = data.find("://")
    if sep_idx == -1:
        return None

    scheme = data[:sep_idx].lower()
    is_realm = "realm" in scheme

    url_body, _, fragment = data[sep_idx + 3:].partition('#')
    main_part, _, query_str = url_body.partition('?')

    at_idx = main_part.rfind('@')
    if at_idx != -1:
        password_raw = main_part[:at_idx]
        host_path_part = main_part[at_idx + 1:]
    else:
        password_raw = ""
        host_path_part = main_part

    password = unquote(password_raw) if '%' in password_raw else password_raw

    params = {}
    stun_servers = []

    if query_str:
        start = 0
        end = len(query_str)

        append_stun = stun_servers.append
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

                if k == 'stun':
                    append_stun(v)
                else:
                    params_set(k, v)

            start = amp_idx + 1

    get = params.get

    slash_idx = host_path_part.find('/')
    if slash_idx != -1:
        hp_part = host_path_part[:slash_idx]
        path_str = host_path_part[slash_idx + 1:]
    else:
        hp_part = host_path_part
        path_str = ""

    if fragment:
        tag = unquote(fragment) if '%' in fragment else fragment
    else:
        tag = genName() + '_hy2'

    node = {
        "tag": tag,
        "type": "hysteria2",
    }

    realm_host = None

    if is_realm:
        realm_proto = "http" if "+http" in scheme else "https"

        if hp_part.startswith('['):
            end_bracket = hp_part.find(']')
            realm_host = hp_part[1:end_bracket]
        else:
            realm_host = hp_part.rpartition(':')[0] or hp_part

        node["realm"] = {
            "server_url": f"{realm_proto}://{hp_part}",
            "token": password,
            "realm_id": path_str,
            "stun_servers": stun_servers,
        }

        node["password"] = get('auth', '')

    else:
        if hp_part.startswith('['):
            end_bracket = hp_part.find(']')
            server = hp_part[1:end_bracket]
            raw_port = hp_part[end_bracket + 2:]
        else:
            server, _, raw_port = hp_part.rpartition(':')
            if not server:
                server = raw_port
                raw_port = ""

        main_port = 443
        port_range = ""

        if raw_port:
            comma_idx = raw_port.find(',')

            if comma_idx != -1:
                p_main = raw_port[:comma_idx]
                p_hop = raw_port[comma_idx + 1:]

                if p_main:
                    main_port = int(p_main)

                port_range = p_hop.replace('-', ':')

            else:
                hyphen_idx = raw_port.find('-')

                if hyphen_idx != -1:
                    main_port = int(raw_port[:hyphen_idx])
                    port_range = raw_port.replace('-', ':')
                else:
                    main_port = int(raw_port)

        mport_raw = get('mport')
        m_ports = mport_raw.replace('-', ':') if mport_raw else port_range

        node["server"] = server
        node["server_port"] = main_port

        if m_ports:
            node["server_ports"] = m_ports

        node["password"] = password or get('auth', '')

    obfs_type = get('obfs')

    if obfs_type and obfs_type != 'none':
        node["obfs"] = {
            "type": obfs_type,
            "password": get('obfs-password') or get('obfs-param') or "",
        }

    sni = get('sni') or get('peer')

    is_insecure = (
        get('insecure') in _TRUE_STRINGS or
        get('allowInsecure') in _TRUE_STRINGS
    )

    if sni and sni.lower() == 'none':
        sni = None
        is_insecure = True

    if sni:
        server_name = sni
    elif is_realm:
        server_name = realm_host
    else:
        server_name = server

    alpn_raw = get('alpn')

    if not alpn_raw or alpn_raw == 'h3':
        alpn_list = ['h3']
    else:
        alpn_list = [a.strip() for a in alpn_raw.split(',')]

    node["tls"] = {
        "enabled": True,
        "server_name": server_name,
        "insecure": is_insecure,
        "alpn": alpn_list,
    }

    return node