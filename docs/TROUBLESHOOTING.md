# トラブルシューティング

## 生成に失敗する / タイムアウトする
- 大きなイメージでは時間がかかります。`SBOM_GENERATION_TIMEOUT` を延長してください (デフォルト 600 秒)。
- ネットワーク越しのプルに時間がかかる場合があります。事前に `docker pull <image>` でキャッシュしておくと改善することがあります。

## 「tool is not installed」と表示される
- Docker イメージ内には Syft / Trivy が含まれています。`docker run -p 8080:8080 sbom-web` で起動してください。
- ローカル実行時は `syft` と `trivy` コマンドをインストールし、PATH に含めてください。

## Trivy が DB 更新を求める
- デフォルトでは `TRIVY_SKIP_DB_UPDATE=true` を設定しています。脆弱性 DB 更新が必要な場合はコンテナ起動時に `-e TRIVY_SKIP_DB_UPDATE=false` を指定し、ネットワーク接続を許可してください。

## プライベートイメージにアクセスできない
- コンテナを起動するホストで `docker login` を行ってから実行してください。
- 必要に応じて `~/.docker/config.json` をコンテナへマウントし、認証情報を共有してください。

## 出力が見づらい
- SBOM 出力は大きくなることがあります。生成後に「Executed command」をコピーし、ローカルで CLI から実行しつつファイルに保存する方法も検討してください。例:
  - Syft: `syft nginx:latest -o spdx-json > sbom.json`
  - Trivy: `trivy sbom --format cyclonedx nginx:latest > sbom.json`
