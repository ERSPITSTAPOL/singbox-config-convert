# singbox-config-convert

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/ERSPITSTAPOL/singbox-config-convert)

A serverless web service for converting proxy subscription links into [sing-box](https://github.com/SagerNet/sing-box) configuration files, designed for one-click deployment on Vercel.

It accepts subscription URLs (URI/Base64) and merges them with a selected config template to produce a ready-to-use sing-box JSON config.

## Features

- **One-click Vercel deployment** — no server setup required
- **Multi-protocol support** — VMess, VLESS, Shadowsocks, ShadowsocksR, Trojan, TUIC, Hysteria, Hysteria2, WireGuard, AnyTLS, SOCKS, HTTP/HTTPS
- **Clash config conversion** — converts Clash-format subscriptions to sing-box outbounds
- **Multiple config templates** — choose from several built-in templates
- **Web UI** — a clean browser interface for generating configs without any tooling

## Supported Protocols

| Protocol | V2 Sub | Clash Sub | Standard URI Format | SingBox Format |
| :----  | :----: | :----: | :----: | :----: |
| http   | ❌ | ✅ | ❌ | ✅ |
| socks5 | ✅ | ✅ | ❌ | ✅ |
| shadowsocks | ✅ | ✅ | ✅ | ✅ |
| vmess  | ✅ | ✅ | ✅ | ✅ |
| trojan | ✅ | ✅ | ✅ | ✅ |
| vless  | ✅ | ✅ | ✅ | ✅ |
| tuic   | ✅ | ✅ | ✅ | ✅ |
| hysteria  | ✅ | ✅ | ✅ | ✅ |
| hysteria2 | ✅ | ✅ | ✅ | ✅ |
| snell | ❌ | ✅ | ❌ | ✅ |
| wireguard | ✅ | ✅ | ❌ | ✅ |
| tailscale | ❌ | ✅ | ❌ | ✅ |
| openvpn | ❌ | ✅ | ❌ | ✅ |

## Project Structure

```
singbox-config-convert/
├── api/
│   ├── app.py              # FastAPI endpoint: handles /config/* conversion requests
│   └── index.py            # Serverless handler: serves the web UI (/)
├── config_template/        # Built-in sing-box config templates (JSON)
│   ├── config1.13.json
│   ├── config1.14.json
│   └── .......
├── parsers/                # Per-protocol URI parsers
│   ├── vmess.py
│   ├── vless.py
│   ├── ss.py
│   ├── ssr.py
│   ├── trojan.py
│   ├── tuic.py
│   ├── hysteria.py
│   ├── hysteria2.py
│   ├── wg.py
│   ├── anytls.py
│   ├── socks.py
│   ├── http.py
│   └── clash2sing.py       # Clash → sing-box outbound converter
├── templates/
│   └── index.html          # Web UI template
├── public/
│   └── favicon.png
├── main.py                 # Core config generation logic
├── tool.py                 # Utility helpers
├── gh_proxy_helper.py      # GitHub proxy support
├── vercel.json             # Vercel routing & function config
├── Pipfile                 # Python dependencies
└── pyproject.toml
```

## Deployment

### Environment Variables

| Variables | Example Value | Purpose |
|:----------|:--------------|:--------|
| RUA       | curl,wget     | Used for simple traffic filtering by User-Agent.|

### Vercel (recommended)

Click the button at the top of this page, or:

1. Fork this repository
2. Import it in the [Vercel dashboard](https://vercel.com/new)
3. Select Application Preset --> Other
4. Add Environment Variables
5. Deploy

### Local development

with uv wrapper
```bash
pip install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv
uv pip install -e .
export RUA="curl,wget"
uv run uvicorn api.app:app --reload --host 127.0.0.1 --port 8000
```

without uv wrapper
```bash
pip install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
uv pip install -e . --system
export RUA="curl,wget"
uvicorn api.app:app --reload --host 127.0.0.1 --port 8000
```

Locking and compiling dependencies
```bash
uv lock
uv pip compile pyproject.toml
```

### Docker

```bash
docker build -t singbox-config-convert .
docker run -d \
  --name singbox-config-convert \
  -p 8080:80 \
  -e RUA=curl,wget \
  singbox-config-convert
```
The service will be available at `http://localhost:8080`.


## Usage

Open the deployed URL in your browser, paste your subscription link(s), pick a config template, and download the generated sing-box config.

The conversion endpoint is also directly accessible:

```
GET /config/?url=<subscription_urlencode>&file=<template_url/index>
```

### config_templates
The template files are similar to sing-box configs, but with some new parameters like `{all}`, `{tag}` , `filter`, which only work with `clash_mode` in `urltest` and `selector` outbounds.
```json
{
  "tag":"proxy",
  "type":"selector",
  "outbounds":[
    "auto",
    "{all}" //All nodes of all subscriptions are added to the location of this tag
  ],
  "filter":[
    {"action":"exclude","keywords":["ˣ²"],"for":["tag_1"]} //This filter will remove nodes containing ˣ² in tag_1
  ]
},
{
  "tag":"netflix",
  "type":"selector",
  "outbounds":[
    "{tag_1}", //Tag with the tag_1's subscribe will be added to this group.
    "{tag_2}" //Tag with the tag_2's subscribe will be added to this group.
  ],
  "filter":[
    {"action":"include","keywords":["sg|tw"]}, // If odes with these names 'sg','tw' they collectively form the netflix group
    {"action":"exclude","keywords":["us"],"for":["tag_1"]} //The "for" is set to tag_1, which means that this rule only works on tag_1's subscribes.
  ]
}
```
- `{all}`: Represents all nodes in all subscriptions. The script will add all nodes to the `outbounds` with this identifier.

- `{tag}` (translated as `{tag}`): The subscribe `tag` set in `current_providers` that the structure in app.py can be used here, representing all nodes in this subscription.Each subscription's tag must be unique.

- `filter`: Optional. Node filtering, an array object where you can add any number of rules, formatted as:
```json
"filter": [
    {"action": "include", "keywords": ["keyword1|keyword2"]},
    {"action": "exclude", "keywords": ["keyword1|keyword2"], "for": ["tag_1"]}
  ]
```
- **Keyword case-sensitive**

- `include`: Add the keywords to be retained, use '|' to connect multiple keywords. Nodes with names containing these keywords will be retained, and other nodes will be deleted.

- `exclude`: Add the keywords to be excluded, use '|' to connect multiple keywords. Nodes with names containing these keywords will be deleted, and other nodes will be retained.

- `for`: Optional. Set the airport `tag`, can be multiple. This rule will only apply to the specified airports, and other airports will ignore this rule.

## Acknowledgements

This project builds upon the work of the following projects:

- [Toperlock/sing-box-subscribe](https://github.com/Toperlock/sing-box-subscribe)
- [gg4924/sing-box-subscribe](https://github.com/gg4924/sing-box-subscribe)

## License

[LGPL-3.0](./LICENSE)

```
GNU LESSER GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
Everyone is permitted to copy and distribute verbatim copies
of this license document, but changing it is not allowed.

This library is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this library. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this library without prior consent.
```