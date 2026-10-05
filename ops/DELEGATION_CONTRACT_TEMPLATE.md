# DELEGATION CONTRACT TEMPLATE

## Objective
何を完成させるか。

## Done when
- [ ] 完了条件1
- [ ] 完了条件2
- [ ] 必要な証拠が揃っている
- [ ] PROJECT_STATEが更新されている

## Allowed actions
- 読み取り
- 低リスクな生成・修正
- Machine Preflight
- 決定的FAILの自己修正と再実行

## Forbidden actions
- Human Gateを越える操作
- Canonical / LOCKの無承認変更
- 未承認runtime
- 公開・送信・金銭・削除・権限変更

## Stop conditions
次の場合のみHuman Ownerへ戻す:
1. Human Gateが必要
2. 権限が不足
3. 仕様同士が衝突
4. 証拠では解消できない重大な未知
5. 事前に定義したretry上限へ到達

## Evidence required
- preflight result
- changed files / artifact identity
- remaining findings
- next Human decision, if any

## Final response
日本語で次だけ返す:
1. 何を完了したか
2. 自動で直した問題
3. 残っている問題
4. Human Ownerが今やること（なければ「なし」）
