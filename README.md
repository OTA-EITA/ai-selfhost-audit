# ai-selfhost-audit

[![ci](https://github.com/OTA-EITA/ai-selfhost-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/OTA-EITA/ai-selfhost-audit/actions/workflows/ci.yml)

n8n・Open WebUI・LiteLLM・Langflow・Flowise を Docker Compose でセルフホストしたときの `docker-compose.yaml` と `.env` を読み、危ない既定値や設定、既知の脆弱性があるバージョンを調べる CLI です。ファイルを読むだけで、Docker やネットワークには触りません。

A read-only CLI that checks the Docker Compose files of self-hosted AI platforms (n8n, Open WebUI, LiteLLM, Langflow, Flowise) for open first-run setup, example secrets, risky switches and image versions with known vulnerabilities. It never talks to Docker or the network.

Dify は [dify-selfhost-audit](https://github.com/OTA-EITA/dify-selfhost-audit) で見ています。

## 対象バージョン

ルールの根拠は、次のバージョンのソースの行にリンクしています（2026-10-29 時点で、公開から 7 日以上たっている最新の安定版）。

| 製品 | 根拠にしたバージョン | 見分け方（image） |
|---|---|---|
| n8n | n8n@2.44.6、n8n-hosting b690a87 | `n8nio/n8n` |
| Open WebUI | v0.12.3 | `open-webui/open-webui` |
| LiteLLM | v1.106.2 | `berriai/litellm` |
| Langflow | v1.12.7 | `langflowai/langflow`、`langflowai/langflow-backend` |
| Flowise | flowise@3.1.4 | `flowiseai/flowise` |

## 使い方

```sh
go install github.com/OTA-EITA/ai-selfhost-audit/cmd/ai-selfhost-audit@latest

# compose ファイルのあるディレクトリで（同じ場所の .env も読む）
ai-selfhost-audit

# ファイルを明示する（--env は複数指定でき、後のファイルが優先）
ai-selfhost-audit --compose docker-compose.yml --env .env --env .env.production

# CI 向け: MEDIUM 以上で失敗、SARIF で出力
ai-selfhost-audit --fail-on medium --format sarif > ai-selfhost.sarif
```

| オプション | 既定値 | 内容 |
|---|---|---|
| `--compose` | `compose.yaml` / `docker-compose.yaml` など | 読む compose ファイル |
| `--env` | compose と同じ場所の `.env` | 変数の展開に使う env ファイル。繰り返し指定可 |
| `--format` | `table` | `table` / `json` / `sarif` |
| `--fail-on` | `high` | この重大度以上があれば終了コード 1。`none` で常に 0 |
| `--all-profiles` | false | `COMPOSE_PROFILES` で無効なサービスもチェックする |
| `--list-rules` | | ルール一覧を表示 |

終了コード: `0` 閾値以上の指摘なし / `1` 閾値以上の指摘あり / `2` 引数やファイルのエラー。

### 読み方の前提

- 製品は、サービスの `image` から見分けます。イメージのタグがバージョン番号なら、既知の脆弱性の修正版と比べます。`latest` や `main` のときはバージョンの比較はせず、GEN006 で知らせます。
- 変数の展開は Compose と同じ規則（`${VAR:-default}`、`${VAR-default}`、`${VAR:?err}`、入れ子、`$$`）で、値は `--env` のファイルからだけ取ります。シェルの環境変数は読みません。
- `environment` に値なしで書かれた変数（`- POSTGRES_PASSWORD`）は、`.env` から取ります。
- 値が空の変数（Flowise の compose のように `KEY=${KEY}` で全部渡す形）は、設定されていないものとして扱います。
- 鍵やパスワードは先頭 4 文字だけを表示します。

## チェック項目

| ID | 製品 | 重大度 | 内容 |
|---|---|---|---|
| GEN001 | any | MEDIUM | Datastore port published on all host interfaces |
| GEN002 | any | INFO | Application port published on all host interfaces |
| GEN003 | any | HIGH | Service runs privileged |
| GEN004 | any | HIGH | Docker socket mounted into a container |
| GEN005 | any | MEDIUM | Service uses the host network |
| GEN006 | any | LOW | Image is not pinned to a version |
| GEN007 | any | MEDIUM | Database password is an example from an official compose file |
| FLW001 | flowise | MEDIUM | First visitor can register as the Flowise owner |
| FLW002 | flowise | HIGH | Flowise version has hard-coded secrets or unauthenticated endpoints |
| FLW003 | flowise | MEDIUM | FLOWISE_USERNAME / FLOWISE_PASSWORD have no effect |
| FLW004 | flowise | HIGH | Custom code may load dangerous modules |
| FLW005 | flowise | HIGH | A Flowise security check is off |
| FLW006 | flowise | HIGH | Custom MCP servers run as local commands |
| FLW007 | flowise | MEDIUM | Flowise allows any origin |
| FLW008 | flowise | MEDIUM | X-Forwarded-For is trusted from any client |
| LGF001 | langflow | HIGH | Langflow auto login gives every visitor superuser access |
| LGF002 | langflow | HIGH | Langflow API calls without a key run as the superuser |
| LGF003 | langflow | HIGH | Langflow superuser password is weak or a sample |
| LGF004 | langflow | MEDIUM | LANGFLOW_SECRET_KEY is short |
| LGF005 | langflow | HIGH | Langflow sign-ups are active immediately |
| LGF006 | langflow | MEDIUM | Langflow webhooks run without authentication |
| LGF007 | langflow | HIGH | A Langflow file or network guard is off |
| LGF008 | langflow | HIGH | Langflow version has vulnerabilities known to be exploited |
| LGF009 | langflow | MEDIUM | Langflow version is below the latest security fixes |
| LLM001 | litellm | HIGH | LiteLLM is allowed to start without a real master key |
| LLM002 | litellm | HIGH | LITELLM_MASTER_KEY is weak |
| LLM003 | litellm | MEDIUM | LITELLM_SALT_KEY is not set |
| LLM004 | litellm | HIGH | LiteLLM version has a known critical authentication flaw |
| LLM005 | litellm | MEDIUM | LiteLLM CORS sends credentials to any origin |
| LLM006 | litellm | MEDIUM | LiteLLM secret redaction in logs is off |
| LLM007 | litellm | MEDIUM | LiteLLM can start MCP servers as local commands |
| N8N001 | n8n | MEDIUM | First visitor can claim the n8n owner account |
| N8N002 | n8n | HIGH | N8N_ENCRYPTION_KEY is an example value |
| N8N003 | n8n | MEDIUM | Task runner auth token is an example value |
| N8N004 | n8n | HIGH | Execute Command node is allowed |
| N8N005 | n8n | HIGH | Workflows can read environment variables |
| N8N006 | n8n | HIGH | File nodes can reach the whole filesystem |
| N8N007 | n8n | HIGH | An n8n safety switch is turned off |
| N8N008 | n8n | MEDIUM | n8n SSRF protection is off |
| N8N009 | n8n | MEDIUM | n8n session cookie is not Secure |
| N8N010 | n8n | HIGH | n8n version has an unpatched expression sandbox escape |
| OWU001 | open-webui | MEDIUM | First visitor can sign up as the Open WebUI admin |
| OWU002 | open-webui | HIGH | Open WebUI authentication is off |
| OWU003 | open-webui | HIGH | WEBUI_SECRET_KEY is a known value |
| OWU004 | open-webui | HIGH | New Open WebUI sign-ups get an active role |
| OWU005 | open-webui | HIGH | Trusted header sign-in with the port published directly |
| OWU006 | open-webui | HIGH | Web fetch may reach private addresses |
| OWU007 | open-webui | HIGH | OpenAI API passthrough is on |
| OWU008 | open-webui | LOW | CORS allows any origin |
| OWU009 | open-webui | HIGH | Open WebUI version lets any website steal a signed-in token |

各ルールの根拠（ソースの行や advisory）は `--format json` の `references` と SARIF の `helpUri` に入っています。

## 公式の compose ファイルに対する結果

`testdata/` には、各プロジェクトが公開している compose ファイルと `.env` の例を、上の表のバージョンのまま入れてあります。

### n8n

```text
SEVERITY  ID      SERVICE   LOCATION               FINDING
HIGH      N8N010  n8n       docker-compose.yml:27  n8n version has an unpatched expression sandbox escape
MEDIUM    GEN007  n8n       .env:8                 Database password is an example from an official compose file
MEDIUM    GEN007  postgres  .env:4                 Database password is an example from an official compose file
MEDIUM    GEN007  postgres  .env:8                 Database password is an example from an official compose file
MEDIUM    N8N001  n8n       docker-compose.yml:27  First visitor can claim the n8n owner account
MEDIUM    N8N003  n8n       .env:10                Task runner auth token is an example value
MEDIUM    N8N008  n8n       docker-compose.yml:27  n8n SSRF protection is off
INFO      GEN002  n8n       docker-compose.yml:42  Application port published on all host interfaces

8 findings: 1 high, 6 medium, 0 low, 1 info
```

### openwebui

```text
SEVERITY  ID      SERVICE     LOCATION                FINDING
MEDIUM    OWU001  open-webui  docker-compose.yaml:11  First visitor can sign up as the Open WebUI admin
LOW       GEN006  open-webui  docker-compose.yaml:11  Image is not pinned to a version
LOW       OWU008  open-webui  docker-compose.yaml:11  CORS allows any origin
INFO      GEN002  open-webui  docker-compose.yaml:22  Application port published on all host interfaces

4 findings: 0 high, 1 medium, 2 low, 1 info
```

### litellm

```text
SEVERITY  ID      SERVICE     LOCATION               FINDING
MEDIUM    GEN001  db          docker-compose.yml:47  Datastore port published on all host interfaces
MEDIUM    GEN001  prometheus  docker-compose.yml:62  Datastore port published on all host interfaces
MEDIUM    GEN007  db          docker-compose.yml:45  Database password is an example from an official compose file
MEDIUM    GEN007  litellm     docker-compose.yml:18  Database password is an example from an official compose file
MEDIUM    LLM003  litellm     docker-compose.yml:2   LITELLM_SALT_KEY is not set
LOW       GEN006  litellm     docker-compose.yml:2   Image is not pinned to a version
INFO      GEN002  litellm     docker-compose.yml:16  Application port published on all host interfaces

7 findings: 0 high, 5 medium, 1 low, 1 info
```

### langflow

```text
SEVERITY  ID      SERVICE   LOCATION               FINDING
MEDIUM    GEN001  postgres  docker-compose.yml:28  Datastore port published on all host interfaces
MEDIUM    GEN007  langflow  docker-compose.yml:10  Database password is an example from an official compose file
MEDIUM    GEN007  postgres  docker-compose.yml:25  Database password is an example from an official compose file
LOW       GEN006  langflow  docker-compose.yml:2   Image is not pinned to a version
INFO      GEN002  langflow  docker-compose.yml:6   Application port published on all host interfaces

5 findings: 0 high, 3 medium, 1 low, 1 info
```

### flowise

```text
SEVERITY  ID      SERVICE  LOCATION                FINDING
MEDIUM    FLW001  flowise  docker-compose.yml:4    First visitor can register as the Flowise owner
MEDIUM    FLW008  flowise  docker-compose.yml:148  X-Forwarded-For is trusted from any client
LOW       GEN006  flowise  docker-compose.yml:4    Image is not pinned to a version
INFO      GEN002  flowise  docker-compose.yml:155  Application port published on all host interfaces

4 findings: 0 high, 2 medium, 1 low, 1 info
```

どの製品も、「最初にアクセスした人が管理者になれる」状態（N8N001、OWU001、FLW001）か、データベースの例のパスワード（GEN007）が出ます。公式の例は手元で試すためのもので、そのまま外に出す前提ではありません。

## 実環境での確認（ai-lab）

`.github/workflows/ai-lab.yml` は、GitHub Actions のランナー上で各製品を公式の compose ファイルから起動し、静的な点検の結果を実際のコンテナで確かめる手動実行専用のワークフローです（`workflow_dispatch` のみ）。公開ポートはすべて 127.0.0.1 に付け替えてから起動し、終わったら `docker compose down -v` で片付けます。手元のマシンやサーバーでは実行しないでください。

2026-10-30 の結果:

| 製品 | 確かめたこと | 結果 |
|---|---|---|
| n8n 2.44.5 | ログインなしで `GET /rest/settings` | `showSetupOnFirstLoad: true`（未設定だと外から分かる） |
| | ログインなしで `POST /rest/owner/setup` | 200。最初に送った人が owner になった |
| | 2 回目の `POST /rest/owner/setup` | 400 `Instance owner already setup` |
| | `- POSTGRES_PASSWORD`（値なし）が `.env` から入るか | 入る（`changePassword`） |
| | 例のパスワード `changePassword` で Postgres にログイン | できた |
| Open WebUI 0.12.3 | ログインなしで `GET /api/config` | `onboarding: true` |
| | 最初のサインアップ | `role: admin` |
| | 2 人目のサインアップ | 403 |
| LiteLLM 1.106.2 | `.env.example` のまま（マスターキーが空） | 起動を拒否（`refused to start: the master key is empty`） |
| | マスターキーを設定して `/health`・`/metrics` をキーなしで | どちらも 401 |
| | 例のパスワード `dbpassword9090` で Postgres にログイン | できた |
| Langflow 1.12.7 | 既定のイメージで `GET /api/v1/auto_login` | 403（自動ログインは無効） |
| | `LANGFLOW_AUTO_LOGIN=true` にして同じリクエスト | 200。スーパーユーザーのトークンが返った |
| | 例のパスワード `langflow` で Postgres にログイン | できた |
| Flowise 3.1.4 | 公式の compose と `.env.example` のまま起動 | 起動しない（空の `LOG_PATH` で `mkdir('')` が失敗、[#6030](https://github.com/FlowiseAI/Flowise/issues/6030)） |
| | パスを `.env` に入れて起動 | 3.1.4 のイメージ自体が起動に失敗（[#6688](https://github.com/FlowiseAI/Flowise/issues/6688)）。今回は確かめられていない |

どの製品も、公式の compose ファイルはアプリのポートをホストの全インターフェースに公開しています（`docker compose config` で確認）。

## 開発

```sh
go test ./...
go vet ./...
```

## License

MIT
