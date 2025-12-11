# Docker SBOM Web GUI

Docker Hub のイメージを対象に、Syft または Trivy を使って SPDX / CycloneDX 形式の SBOM を生成するシンプルな Web GUI です。ブラウザからイメージ名を入力して SBOM を取得でき、実行したコマンドも併せて確認できます。

## 主な特徴
- Syft または Trivy を選択して SBOM を生成
- SPDX(JSON) / CycloneDX(JSON) の両フォーマットに対応
- Web フォームからイメージ参照を入力するだけで実行
- 実行したコマンドを表示し、CLI での再現を容易に
- Docker イメージとして配布・実行可能

## 前提
- Docker 環境 (推奨)
- もしくはローカルで動かす場合: Python 3.11 以上、`syft` と `trivy` コマンドが PATH に存在すること

## アーキテクチャ
- **backend**: Flask API (`/api/sbom`, `/api/download/<token>`) で Syft/Trivy を実行し、生成した SBOM を `/tmp/sboms` に保存してパスをログ出力します。
- **frontend**: Nginx が静的 HTML/JS を配信し、`/api/*` を backend にプロキシします。

## クイックスタート (docker-compose)
```bash
docker-compose up -d --build
```
ブラウザで `http://localhost:8080` を開き、イメージ名・ツール・フォーマットを選んで実行します。停止は `docker-compose down`。

## 単体実行 (backend を直接起動する場合)
```bash
docker build -t sbom-backend .
docker run --rm -p 8080:8080 sbom-backend
```
API は `POST /api/sbom` に JSON で `image_ref`, `tool`, `format` を渡します。

## ローカル実行 (開発用)
```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Syft / Trivy を PATH にインストールした上で
FLASK_APP=app.py flask run --port 8080
```

## 使い方
1) Docker イメージ参照を入力 (例: `nginx:latest` または `library/nginx:1.25`).  
2) ツールを選択 (Syft / Trivy).  
3) フォーマットを選択 (SPDX JSON / CycloneDX JSON).  
4) 「Generate SBOM」をクリックすると、SBOM 出力と実行コマンドが表示されます。

## 環境変数
- `PORT` — アプリの待受ポート (デフォルト `8080`)
- `FLASK_SECRET` — セッション用シークレットキー
- `SBOM_GENERATION_TIMEOUT` — SBOM 生成のタイムアウト秒 (デフォルト 600)
- `TRIVY_SKIP_DB_UPDATE` — Trivy の DB 更新スキップ (Dockerfile では `true` 設定)
- `TRIVY_NO_PROGRESS` — Trivy のプログレス非表示
- `DELETE_IMAGE_AFTER_SUCCESS` — 成功時に `docker image rm -f <image>` を実行してイメージを掃除 (デフォルト: 無効)。Docker CLI が使えない環境では自動スキップ。
- `SBOM_OUTPUT_DIR` — SBOM を保存するディレクトリ (デフォルト `/tmp/sboms`, docker-compose ではボリュームにマウント)
- `SYFT_REGISTRY_AUTH_USERNAME` / `SYFT_REGISTRY_AUTH_PASSWORD`, `TRIVY_USERNAME` / `TRIVY_PASSWORD` — プライベートレジストリ用の認証情報（フロントからも入力可能）
- nginx のタイムアウト: `frontend/nginx.conf` で `/api/` への `proxy_read_timeout` などを 600s に延長済み。長時間かかる SBOM 生成に対応。

## 仕組み (概要)
`app.py` が Flask でフォームを受け取り、選択されたツール・フォーマットに応じて以下を実行します。
- Syft: `syft <image> -o spdx-json|cyclonedx-json`
- Trivy: `trivy sbom --format spdx-json|cyclonedx <image>`
標準出力をそのまま Web 上に表示し、失敗時はエラー内容を返します。

## よくあるポイント
- Docker Hub のプライベートイメージを扱う場合は、コンテナを起動するホストで `docker login` 済みであることを確認してください。
- 大きなイメージでは生成に時間がかかることがあります。`SBOM_GENERATION_TIMEOUT` を調整してください。
- Trivy で脆弱性 DB の更新が必要な場合は、`TRIVY_SKIP_DB_UPDATE=false` を設定し、ネットワーク接続を許可してください。

## 追加ドキュメント
- 詳細な手順: `docs/USAGE.md`
- トラブルシューティング: `docs/TROUBLESHOOTING.md`

## ライセンス
プロジェクトのライセンス方針に合わせて適宜追加してください。
