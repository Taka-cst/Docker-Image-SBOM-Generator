# Docker SBOM Web GUI

Syft / Trivy を使って SPDX / CycloneDX 形式の SBOM を生成するシンプルな Web GUI です。ブラウザからイメージ名を入力するだけで SBOM を取得でき、実行したコマンドも確認できます。現在は「単体生成」と「4 パターン ZIP」に絞って動作します。

## 特長
- Syft または Trivy を選んで SBOM を生成（SPDX JSON / CycloneDX JSON 対応）。
- フロントエンドからイメージ参照を入力するだけで利用可能。
- 実行コマンドを表示し、CLI での再現が容易。
- 単体イメージでも 4 パターン（Syft/Trivy × SPDX/CycloneDX）を一括 ZIP でダウンロード可能。
- Docker コンテナとして実行できるため、ローカルに Syft/Trivy を用意しなくても試せます。

## 前提
- Docker 環境（推奨）。  
  またはローカル実行の場合は Python 3.11 以降と、`syft` と `trivy` が PATH にあること。

## クイックスタート（docker-compose）
```bash
docker-compose up -d --build
```
ブラウザで `http://localhost:8080` を開きます。停止は `docker-compose down` です。

## backend だけを起動する場合
```bash
docker build -t sbom-backend .
docker run --rm -p 8080:8080 sbom-backend
```
この場合は別途フロントエンドを用意するか、`POST /api/sbom` に JSON で `image_ref`, `tool`, `format` を送信してください。

## ローカル開発の例
```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Syft / Trivy を PATH にインストールした上で
FLASK_APP=app.py flask run --port 8080
```

## 使い方（フロントエンド）
- 単体生成: イメージ名を入れ、ツールとフォーマットを選んで「SBOM を生成」を押すと結果とダウンロードリンクが表示されます。
- 4 パターン ZIP: イメージ名（必要なら認証情報）を入れ、「4 パターン ZIP」を押すと Syft/Trivy × SPDX/CycloneDX の 4 つをまとめて取得できます。

## API 一覧
- `POST /api/sbom`  
  body: `{"image_ref": "...", "tool": "syft|trivy", "format": "spdx|cyclonedx", "registry_username": "...", "registry_password": "..."}`  
  response: `{success, command, sbom, download_token, download_filename, saved_path, cleanup_message}`
- `POST /api/sbom/all`  
  body: `{"image_ref": "...", "registry_username": "...", "registry_password": "..."}`  
  単体イメージに対して 4 パターン（Syft/Trivy × SPDX/CycloneDX）を生成し、ZIP を返却。response には `zip_download_token`, `zip_filename`, `records` などが含まれます。
- `GET /api/download/<token>`  
  生成済み（キャッシュ済み）の SBOM または ZIP をダウンロード。

## 主な環境変数
- `PORT`: リッスンポート（デフォルト 8080）
- `SBOM_OUTPUT_DIR`: SBOM 保存先（デフォルト `/tmp/sboms`）
- `DELETE_IMAGE_AFTER_SUCCESS`: 成功後に `docker image rm -f <image>` を実行（デフォルト無効）
- `SBOM_GENERATION_TIMEOUT`: タイムアウト秒数（デフォルト 600）
- `TRIVY_SKIP_DB_UPDATE`: Trivy DB 更新スキップ（デフォルト true）
- `TRIVY_NO_PROGRESS`: Trivy のプログレス非表示
- `SYFT_REGISTRY_AUTH_USERNAME` / `SYFT_REGISTRY_AUTH_PASSWORD`
- `TRIVY_USERNAME` / `TRIVY_PASSWORD`
- `FLASK_SECRET`: セッション用シークレット

## よくあるポイント
- 大きなイメージは時間がかかるため、`SBOM_GENERATION_TIMEOUT` を調整してください。
- プライベートイメージを扱う場合、ホストで `docker login` を済ませ、必要に応じて `~/.docker/config.json` を backend コンテナにマウントしてください。
- Trivy の DB 更新が必要な場合は `TRIVY_SKIP_DB_UPDATE=false` にし、ネットワーク接続を許可してください。

より詳細な手順は `docs/USAGE.md` を参照してください。
