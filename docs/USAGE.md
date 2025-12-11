# 利用ガイド

## 1. 起動方法
### docker-compose (frontend + backend)
```bash
docker-compose up -d --build
```
ブラウザで `http://localhost:8080` を開きます。停止は `docker-compose down`。

### backend を直接起動
```bash
docker build -t sbom-backend .
docker run --rm -p 8080:8080 sbom-backend
```
この場合は別途フロントエンドを用意するか、`POST /api/sbom` に JSON で `image_ref`, `tool`, `format` を送信してください。

## 2. フロントエンドでの SBOM 生成手順
1) Docker image reference にイメージ参照を入力 (例: `nginx:latest`).  
2) SBOM tool で Syft または Trivy を選択。  
3) SBOM format で SPDX JSON か CycloneDX JSON を選択。  
4) Generate SBOM を押す。  
5) コマンド、SBOM 出力、保存先パス、ダウンロードリンクが表示されます。

## 3. バックエンド API
- `POST /api/sbom`  
  - body: `{"image_ref": "...", "tool": "syft|trivy", "format": "spdx|cyclonedx", "registry_username": "...", "registry_password": "..."}`  
  - response: `{success, command, sbom, download_token, download_filename, saved_path, cleanup_message}`
- `GET /api/download/<token>`: キャッシュ済み SBOM をダウンロード
- ログには SBOM の保存先パスが出力されます。

## 4. フォーマットとツールの対応
- Syft: `-o spdx-json` / `-o cyclonedx-json`
- Trivy: `--format spdx-json` / `--format cyclonedx`

## 5. 環境変数の主な項目
- `PORT`: 待受ポート (default 8080)
- `SBOM_OUTPUT_DIR`: SBOM 保存先 (default `/tmp/sboms`)
- `DELETE_IMAGE_AFTER_SUCCESS`: SBOM 生成成功後に `docker image rm -f <image>` で削除 (Docker CLI がない場合は自動スキップ)
- `SBOM_GENERATION_TIMEOUT`: タイムアウト秒 (default 600)
- `TRIVY_SKIP_DB_UPDATE`: Trivy の DB 更新スキップ (default true)
- `TRIVY_NO_PROGRESS`: Trivy のプログレス非表示
- `SYFT_REGISTRY_AUTH_USERNAME` / `SYFT_REGISTRY_AUTH_PASSWORD`, `TRIVY_USERNAME` / `TRIVY_PASSWORD`: プライベートレジストリ用の認証情報（フロントからも入力可能）
- `FLASK_SECRET`: セッション用シークレット
- nginx タイムアウト: `/api/` への `proxy_read_timeout` 等を 600s に設定済み（`frontend/nginx.conf`）

## 6. プライベートイメージを扱う場合
- コンテナを起動するホストで `docker login` を行ってください。
- 必要に応じて `~/.docker/config.json` を backend コンテナにマウントし、認証情報を共有してください。

## 7. トラブルシュートのヒント
- 生成に時間がかかる: `SBOM_GENERATION_TIMEOUT` を延長。イメージサイズを確認。
- Trivy で DB 更新が必要: `TRIVY_SKIP_DB_UPDATE=false` を設定し、ネットワーク接続を許可。
- 「tool not installed」エラー: backend イメージで実行するか、ローカルに Syft/Trivy をインストール。
