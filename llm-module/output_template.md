# Template de sortie finale — llm-module

## Statut d'implémentation

| Section | Phase | Implémenté |
|---|---|---|
| `decision_metadata` | Phase 1 — vote sur quels scans lancer | ✅ |
| `scan_analysis.*.raw_result` | Phase 2 — résultats bruts des scanners | ✅ |
| `scan_analysis.*.llm_summary` | Phase 3 — résumé LLM des résultats | ✅ |
| `scan_reasoning.workers` | Phase 3 — raisonnement de chaque worker sur les scans | ✅ |
| `scan_reasoning.arbiter` | Phase 3 — synthèse arbitre → score final | ✅ |
| `verdict` | Phase 3 — décision finale + score | ✅ |
| `alternatives` | Phase 3 — alternatives suggérées par le LLM | ✅ |

---

## JSON

```json
{
  "pull_id": "550e8400-e29b-41d4-a716-446655440003",
  "image": "library/alpine:3.18",
  "analysed_at": "2026-04-23T13:14:02Z",

  "verdict": {
    "decision": "DENY",
    "vulnerability_score": 7.5,
    "confidence": 0.93,
    "rationale": "2 CVEs critiques dans busybox et musl-libc combinés à 3 règles compliance échouées dont l'absence d'utilisateur non-root. Worker 2 et Worker 3 convergent sur un score élevé avec des arguments spécifiques et vérifiables."
  },

  "scan_analysis": {
    "static": {
      "executed": true,
      "llm_summary": "2 CVEs critiques dans busybox et musl-libc. Mise à jour vers alpine:3.20 recommandée.",
      "raw_result": {
        "request_id": "uuid",
        "status": "COMPLETE",
        "summary": {
          "vulnerabilities_total": 30,
          "severity_count": {
            "critical": 2,
            "high": 4,
            "medium": 21,
            "low": 3,
            "unknown": 0
          }
        },
        "findings": [
          {
            "cve_id": "CVE-XXXX-XXXX",
            "package": "busybox",
            "installed_version": "1.36.1-r0",
            "fixed_version": "1.36.1-r1",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "title": "Example critical vulnerability"
          }
        ]
      }
    },
    "compliance": {
      "executed": true,
      "llm_summary": "3 règles échouées dont NON_ROOT_USER et SAFE_ENTRYPOINT. 14 règles passées.",
      "raw_result": {
        "status": "FAIL",
        "summary": {
          "pass": 14,
          "warn": 1,
          "fail": 3
        },
        "findings": [
          {
            "rule_id": "NON_ROOT_USER",
            "status": "FAIL",
            "message": "Container runs as root user"
          },
          {
            "rule_id": "SAFE_ENTRYPOINT",
            "status": "FAIL",
            "message": "Entrypoint /bin/sh may allow arbitrary command execution"
          },
          {
            "rule_id": "MAINTAINER_LABEL",
            "status": "WARN",
            "message": "No maintainer label found"
          }
        ]
      }
    },
    "dynamic": {
      "executed": false,
      "llm_summary": null,
      "raw_result": null
    }
  },

  "scan_reasoning": {
    "workers": [
      {
        "model": "minimax/minimax-m2.7",
        "status": "failed",
        "vulnerability_score": null,
        "confidence": null,
        "reasoning": null
      },
      {
        "model": "qwen/qwen3.5-35b-a3b",
        "status": "ok",
        "vulnerability_score": 7.0,        "confidence": 0.88,
        "reasoning": "Les 2 CVEs critiques dans busybox sont exploitables à distance selon leur description. Le fait que le container tourne en root amplifie le risque — une exploitation réussie donne un accès root immédiat. Je note aussi que 4 CVEs HIGH ne sont pas négligeables pour un container de production. Score 7.0."
      },
      {
        "model": "google/gemma-4-31b-it",
        "status": "ok",
        "vulnerability_score": 8.0,
        "confidence": 0.95,
        "reasoning": "CVE-XXXX-XXXX dans busybox a un CVSS de 9.8, ce qui est extrêmement sévère. Combiné à l'absence de USER non-root et à l'entrypoint /bin/sh, cette image offre une surface d'attaque maximale. 3 règles compliance échouées sur des points critiques. Je monte à 8.0 car le risque cumulé est significatif."
      }
    ],
    "arbiter": {
      "model": "mistralai/mistral-small-2603",
      "vulnerability_score": 7.5,
      "confidence": 0.93,
      "reasoning": "Worker 2 (score 7.0) et Worker 3 (score 8.0) convergent sur une évaluation haute avec des arguments spécifiques et vérifiables. Worker 3 justifie son score plus élevé par le CVSS 9.8 de busybox et l'amplification du risque due au root. Je retiens 7.5 comme compromis raisonnable entre les deux évaluations. Worker 1 a échoué donc non pris en compte."
    }
  },

  "alternatives": [
    {
      "image": "cgr.dev/chainguard/alpine-base:latest",
      "reason": "Variante Alpine zéro CVE connu, non-root par défaut, compatible workloads Alpine standard.",
      "confidence": 0.90
    },
    {
      "image": "gcr.io/distroless/static-debian12",
      "reason": "Sans shell ni gestionnaire de paquets, surface d'attaque minimale. Adaptée si le conteneur n'exécute qu'un binaire statique.",
      "confidence": 0.70
    }
  ],

  "decision_metadata": {
    "workers": [
      {
        "model": "minimax/minimax-m2.7",
        "status": "failed",
        "run_static_scan": null,
        "run_compliance_scan": null,
        "run_dynamic_scan": null,
        "confidence": null,
        "reasoning": null
      },
      {
        "model": "qwen/qwen3.5-35b-a3b",
        "status": "ok",
        "run_static_scan": false,
        "run_compliance_scan": true,
        "run_dynamic_scan": false,
        "confidence": 0.85,
        "reasoning": "Alpine 3.18 tourne en root par défaut, entrypoint /bin/sh à vérifier..."
      },
      {
        "model": "google/gemma-4-31b-it",
        "status": "ok",
        "run_static_scan": true,
        "run_compliance_scan": true,
        "run_dynamic_scan": false,
        "confidence": 1.00,
        "reasoning": "Alpine 3.18.12 contient un minirootfs complet, CVEs potentiels dans les packages de base..."
      }
    ],
    "arbiter": {
      "model": "mistralai/mistral-small-2603",
      "reasoning": "Worker 2 et Worker 3 fournissent des arguments spécifiques et vérifiables pour les deux scans. Worker 2 manque le scan statique mais Worker 3 le couvre. Décision : static + compliance."
    }
  }
}
```
