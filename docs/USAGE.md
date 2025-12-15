# 利用ガイド

## 1. 起動方法

### docker-compose（frontend + backend）
```bash
docker-compose up -d --build
```
ブラウザで `http://localhost:8080` にアクセスします。停止は `docker-compose down` です。

### backend を直接起動する場合
```bash
docker build -t sbom-backend .
docker run --rm -p 8080:8080 sbom-backend
```
この場合は別途フロントエンドを用意するか、`POST /api/sbom` に JSON で `image_ref`, `tool`, `format` を送信してください。

## 2. フロントエンドでの SBOM 生成

### 2-1. 単体生成（1 パターン）
1. Docker image reference にイメージ名を入力（例: `nginx:latest`）。
2. SBOM tool（Syft/Trivy）と SBOM format（SPDX/CycloneDX）を選択。
3. 必要に応じてレジストリの認証情報を入力。
4. 「SBOM を生成」を押すと結果・保存先・ダウンロードリンクが表示されます。

### 2-2. 4 パターンを ZIP で取得
1. イメージ名と必要なら認証情報を入力。
2. 「4 パターン ZIP」を押すと、Syft/Trivy × SPDX/CycloneDX の 4 ファイルをまとめて生成し、ZIP でダウンロードできます。

## 3. バックエンド API
- `POST /api/sbom`  
  - body: `{"image_ref": "...", "tool": "syft|trivy", "format": "spdx|cyclonedx", "registry_username": "...", "registry_password": "..."}`  
  - response: `{success, command, sbom, download_token, download_filename, saved_path, cleanup_message}`
- `POST /api/sbom/all`  
  - body: `{"image_ref": "...", "registry_username": "...", "registry_password": "..."}`  
  - 単体イメージに対して 4 パターンを生成し、ZIP を返却。response には `zip_download_token`, `zip_filename`, `records` などが含まれます。
- `GET /api/download/<token>`  
  - 生成済み（キャッシュ済み）の SBOM または ZIP をダウンロード。

## 4. フォーマットとツール
- Syft: `-o spdx-json` / `-o cyclonedx-json`
- Trivy: `--format spdx-json` / `--format cyclonedx`

## 5. 主な環境変数
- `PORT`: リッスンポート（デフォルト 8080）
- `SBOM_OUTPUT_DIR`: SBOM の保存先（デフォルト `/tmp/sboms`）
- `DELETE_IMAGE_AFTER_SUCCESS`: SBOM 生成後に `docker image rm -f <image>` を実行（デフォルト無効）
- `SBOM_GENERATION_TIMEOUT`: タイムアウト秒数（デフォルト 600）
- `TRIVY_SKIP_DB_UPDATE`: Trivy DB 更新スキップ（デフォルト true）
- `TRIVY_NO_PROGRESS`: Trivy のプログレス非表示
- `SYFT_REGISTRY_AUTH_USERNAME` / `SYFT_REGISTRY_AUTH_PASSWORD`
- `TRIVY_USERNAME` / `TRIVY_PASSWORD`
- `FLASK_SECRET`: セッション用シークレット

## 6. トラブルシュートのヒント
- 時間がかかる場合: `SBOM_GENERATION_TIMEOUT` を延長。イメージサイズやネットワークを確認。
- Trivy の DB 更新が必要な場合: `TRIVY_SKIP_DB_UPDATE=false` に変更し、ネットワーク接続を許可。
- 「tool not installed」エラー: backend コンテナで実行するか、ローカルに Syft/Trivy をインストール。
- プライベートイメージ: コンテナを起動するホストで `docker login` を実行し、必要なら `~/.docker/config.json` を backend にマウント。
