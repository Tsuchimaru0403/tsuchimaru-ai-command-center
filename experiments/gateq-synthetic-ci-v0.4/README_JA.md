# Gate Q 合成CI v0.4 — GitHub試験PR（非必須）

このフォルダーは **練習用の合成データだけ**を検証する試作品です。
Gate Qの本物の候補、秘密鍵、承認文書、Replay ledger、Runtimeを読み込まず、実行しません。

- GitHub Actionsの試験用workflow: `.github/workflows/gateq-synthetic-v04.yml`
- `pull_request` のみ（`pull_request_target` は使わない）。読み取り権限のみ。
- このフォルダーまたはworkflowファイルを変更したPRだけで起動します。**必須チェックには指定しません**。
- `gateq_ci_prototype.py` は通常の合成fixtureを構造検査する試作品です。`trusted` モードは常にブロックします。
- 合成検査でPASSになっても `provenance=UNVERIFIED`、`canonical=false`、`required_check_eligible=false`、`may_authorize_runtime=false` です。
- 状態記録は合成fixtureの形式検査であり、実際の `ops/states/ai-command-center.json` を変更したり、解釈したりしません。
- このPRはドラフトです。**マージ・保護ルール変更・正式版LOCKは別途Human Ownerの承認が必要**です。

実行するのはPython標準ライブラリだけを使った74件のunittestです。合成ZIP等のfixtureはOSの一時フォルダーで生成し、後で消去します。依存ライブラリのインストールやネットワークアクセスは必要ありません。

ローカル相当の確認:

```sh
python -m unittest discover -v -s experiments/gateq-synthetic-ci-v0.4 -p 'test_*.py'
```

なお、旧版の24件の追加プローブは別の凍結版ZIPに依存するため、この公開PRには含めません（過去の監査証拠にのみ保持）。**GitHubでの実測結果はPRのChecksで別途確認してください。**

Gate Q本体: **HOLD / NOT LOCKED**。v1.55 R2: **NOT CANONICAL**。
