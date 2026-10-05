# AI OPERATING EFFICIENCY POLICY v1

Status: ACTIVE
Effective: 2026-10-05
Scope: AI司令室 / Gate Q / Minecraft甲子園 / NOTE AI EDITORIAL / 色彩夢・YouTube・Web制作

## Goal

人間をAI間の中継係にしない。品質を落とさず、Human Ownerの介入回数と再監査回数を減らす。

Primary KPI: **Human Interventions per Deliverable (HIPD)**

補助KPI:
- Fresh Audit retry count
- AI conversation turns per deliverable
- Preflight failure rate
- Repeat finding rate
- Time from task start to Human Gate

## 1. AI finding -> regression test

AI監査で見つかったうち、機械的に判定できるfindingは、修正と同時に回帰テストへ昇格する。

原則:
1. findingを分類する: deterministic / semantic / runtime-only
2. deterministic findingは `ops/regression/KNOWN_FINDINGS.json` に登録する
3. preflightで再発を検出できるようにする
4. 同じfindingをFresh Auditorに再発見させない

Fresh Auditorは「意味・設計・証拠の十分性」へ集中する。

## 2. Machine Preflight first

標準ゲート:

```
Machine Preflight
  -> AI Semantic Review
    -> Fresh Independent Audit (risk HIGH only)
      -> Human Gate (where required)
```

Machine Preflight対象:
- hash / manifest / file count
- required files / names
- JSON shape / required fields
- forbidden values
- candidate/canonical identity
- lock/binding references
- deterministic invariants

## 3. PROJECT_STATE as the handoff SSOT

チャットを状態の正本にしない。

各プロジェクトは `ops/states/*.json` に最低限以下を持つ:
- project_id
- as_of
- risk_tier
- current_stage
- status
- canonical
- locked
- last_pass
- open_findings
- next_action
- human_approval_required
- source_of_truth

新しいAIセッションは、過去チャット全文より先にPROJECT_STATEを読む。

## 4. Completion-contract delegation

3往復以上になりそうな作業は、相談型ではなく完了条件付き委任へ変える。

委任時に必ず定義する:
- objective
- done_when
- allowed_actions
- forbidden_actions
- stop_conditions
- evidence_required
- output_summary

AIは低リスクな中間判断でHuman Ownerへ戻さない。
Human Gate、権限不足、仕様衝突、重大な未知が出た時だけ停止する。

## 5. Risk-based audit

### LOW
例: 要約、定型整形、公開前でない下書き、可逆な整理
- AI self-check
- Fresh Audit不要

### MEDIUM
例: note/動画の事実整理、Web変更候補、Minecraft静的生成
- Machine Preflight
- AI review
- 必要時Human review

### HIGH
例: Gate Q、Canonical/LOCK変更、runtime、権限、公開、金銭、不可逆変更
- Machine Preflight
- AI semantic review
- Fresh Independent Audit
- Human Gate

監査強度は「失敗時の損失」で決める。全プロジェクトをGate Qと同じ厳しさにはしない。

## 6. Model routing

- Instant / Low: 整理、形式変換、manifest照合、handoff、定型preflight
- Medium: ログ分析、原因候補整理、記事/動画構成、通常レビュー
- High: 設計、remediation、Fresh Independent Audit、重大な矛盾解決、最終Gate判断

高思考モデルをhash一致確認などの決定的処理に使わない。

## Human Owner boundary

以下は従来どおりHuman Owner承認を必要とする:
- Canonical / LOCK変更
- Runtime実行や重要環境変更
- 公開・送信・金銭・削除
- 権限付与・共有設定
- 自動化権限の昇格

## Migration rule

途中導入を許可する。
既存の証跡・LOCK・canonical成果物は書き換えない。
新ルールは「次に触る作業」から適用し、過去成果物の全面再監査は要求しない。
