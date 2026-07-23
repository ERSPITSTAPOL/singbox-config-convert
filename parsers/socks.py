from tool import genName, b64Decode
from urllib.parse import unquote

def parse(data: str) -> dict:
    hash_idx = data.rfind('#')
    if hash_idx != -1:
        main_part_full = data[:hash_idx]
        tag_source = data[hash_idx + 1:]
    else:
        main_part_full = data
        tag_source = ""

    scheme_idx = main_part_full.find('://')
    if scheme_idx != -1:
        raw_netloc = main_part_full[scheme_idx + 3:]
    else:
        raw_netloc = main_part_full

    if raw_netloc.endswith('/'):
        raw_netloc = raw_netloc[:-1]

    try:
        netloc = b64Decode(raw_netloc).decode('utf-8')
    except Exception:
        netloc = raw_netloc

    at_idx = netloc.rfind('@')
    if at_idx != -1:
        user_pass_str = netloc[:at_idx]
        hp_part = netloc[at_idx + 1:]
    else:
        raw_at_idx = raw_netloc.rfind('@')
        if raw_at_idx != -1:
            hp_part = raw_netloc[raw_at_idx + 1:]
            user_pass_str = netloc
        else:
            user_pass_str = ""
            hp_part = netloc

    if hp_part.startswith('['):
        r_idx = hp_part.rfind(']')
        server = hp_part[1:r_idx]
        p_part = hp_part[r_idx + 1:]
        if p_part.startswith(':'):
            server_port = int(p_part[1:])
        else:
            server_port = 1080
    else:
        r_idx = hp_part.rfind(':')
        if r_idx != -1:
            p_str = hp_part[r_idx + 1:]
            if p_str.isdigit():
                server = hp_part[:r_idx]
                server_port = int(p_str)
            else:
                server = hp_part
                server_port = 1080
        else:
            server = hp_part
            server_port = 1080

    if tag_source:
        tag = unquote(tag_source) if '%' in tag_source else tag_source
    else:
        tag = genName() + '_socks'

    node = {
        'tag': tag,
        'type': 'socks',
        'version': '5',
        'server': server,
        'server_port': server_port,
        'udp_over_tcp': {}
    }

    if user_pass_str:
        colon_idx = user_pass_str.find(':')
        if colon_idx != -1:
            node['username'] = user_pass_str[:colon_idx]
            node['password'] = user_pass_str[colon_idx + 1:]
        else:
            node['username'] = user_pass_str
            node['password'] = ""

    return node