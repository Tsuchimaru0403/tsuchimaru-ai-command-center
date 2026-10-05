# tsuchimaru-ai-command-center

## AI運用効率化 v1

2026-10-05から、既存のCanonical / LOCK /監査証跡を変更せず、次に触る作業から段階導入します。

- 共通方針: `ops/AI_OPERATING_EFFICIENCY_POLICY_v1.md`
- 完了条件付き委任: `ops/DELEGATION_CONTRACT_TEMPLATE.md`
- プロジェクト状態: `ops/states/*.json`
- 回帰finding台帳: `ops/regression/KNOWN_FINDINGS.json`
- 機械Preflight: `python ops/preflight.py`
- CI: `.github/workflows/ops-preflight.yml`

### 標準フロー

```
Machine Preflight
  -> AI Semantic Review
    -> Fresh Independent Audit (HIGH risk only)
      -> Human Gate (where required)
```

Primary KPI: **Human Interventions per Deliverable (HIPD)**

狙いは、Human OwnerがAI同士の中継係になる回数を減らし、Fresh Auditを機械では判定できない論点へ集中させることです。
