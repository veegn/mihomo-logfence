# mihomo-logfence

`mihomo-logfence` is a small Rust service that watches Mihomo (Clash.Meta) log output over WebSocket, captures failed connections, and generates a Clash-compatible rule provider file in real time. It also ships with a web UI for inspecting captured domains, managing a blacklist, and changing per-domain rule types.

## What it does

- Monitors Mihomo logs over WebSocket and reconnects automatically if the connection drops.
- Extracts failed domains and IPs, then writes `dynamic_rule.yaml` in Clash Rule Provider format.
- Lets you blacklist domains from the UI or API.
- Lets you change each captured entry's rule type from the UI or API.
- Persists runtime state on disk so the service can restart without losing data.

## Web UI

The current UI can edit these configuration fields:

- `wsUrl`
- `minHitCount`
- `ruleTtlDays`
- `cidrAggThreshold`

The UI does not currently expose inputs for `filterKeyword` or `matchRegex`. Those values are still part of the stored configuration and are preserved when the UI saves changes.

The domain list UI supports these actions:

- Change rule type with the `Auto`, `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `IP-CIDR`, and `IP-CIDR6` options.
- Add a domain to the blacklist.
- Remove a captured domain entry.
- Remove a domain from the blacklist.

## Run locally

```bash
cargo run --release
```

The service listens on `http://localhost:3000`.

## Docker

The container uses `/data` as its runtime directory and `/public` as the static asset directory.

```bash
docker build -t mihomo-logfence .

docker run -d \
  -p 3000:3000 \
  -v ./data:/data \
  --name mihomo-logfence \
  mihomo-logfence
```

Runtime files are written under `/data` inside the container. Mount that directory if you want persistence across restarts.

## Runtime files

The service creates and updates these files in `DATA_DIR`:

- `config.json`
- `entries.json`
- `blacklist.json`
- `dynamic_rule.yaml`

`DATA_DIR` defaults to the current working directory when unset. `PUBLIC_DIR` defaults to `DATA_DIR/public`.

## API

Current HTTP endpoints:

- `GET /dynamic_rule.yaml` returns the generated rule file.
- `GET /api/status` returns WebSocket connection status.
- `GET /api/config` returns the full persisted configuration.
- `POST /api/config` updates the configuration and reconnects the WebSocket client.
- `GET /api/domains` returns the captured domain list plus the blacklist.
- `DELETE /api/domains` removes a captured domain entry.
- `POST /api/domains/rule-type` updates a captured domain's rule type.
- `POST /api/blacklist` adds a domain to the blacklist.
- `POST /api/blacklist/remove` removes a domain from the blacklist.

`GET /api/domains` returns a JSON object with two top-level arrays:

- `domains`
- `blacklist`

Each domain entry includes `domain`, `hit_count`, `first_seen`, `last_seen`, `rule_type`, `resolved_rule_type`, and `in_yaml`.

- `rule_type` is the persisted value stored for the entry and can remain `auto`.
- `resolved_rule_type` is the effective rule type currently used when generating YAML.

## Output format

`dynamic_rule.yaml` is generated as a Clash classical Rule Provider file. The current output can contain:

- `IP-CIDR`
- `IP-CIDR6`
- `DOMAIN-SUFFIX`
- `DOMAIN-KEYWORD`
- `DOMAIN`

Entries are ordered deterministically before being written to disk.

## Mihomo config example

```yaml
rule-providers:
  logfence:
    type: http
    behavior: classical
    url: "http://<your-host>:3000/dynamic_rule.yaml"
    interval: 300

rules:
  - RULE-SET,logfence,<your-proxy-group>
```

## Project layout

```
mihomo-logfence/
  src/main.rs
  public/index.html
  Cargo.toml
  Dockerfile
```

## License

MIT
