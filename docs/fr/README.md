# RuleScope

**RuleScope** est un moteur de gouvernance CLI-first pour les catalogues Sigma et les règles de détection.
Il aide les ingénieurs détection à évaluer la qualité des règles, expliquer les détections faibles, comparer des packs baseline vs candidat, et imposer des portes de régression en CI avant que le contenu n'atteigne la production.

## Ce qu'il fait

- **Scan** : évalue un pack de règles sur 7 axes — métadonnées, bruit, structure, mapping ATT&CK, maintenabilité, faiblesse analytique et documentation.
- **Explain** : explique pourquoi une règle est faible, avec des recommandations de remédiation priorisées.
- **Compare** : compare des packs baseline vs candidat et remonte les **régressions sémantiques** (wildcards ajoutés, perte de sélecteurs, inflation de sévérité…).
- **Report** : génère des rapports HTML (avec radar chart, filtres et résumé exécutif), Markdown, JSON ou SARIF.
- **Gate** : contrôle les pull requests et les releases avec des budgets de gouvernance déterministes.
- **Maintainers** : identifie les hotspots de dette pour les mainteneurs du catalogue.
- **Navigator** : exporte des couches ATT&CK Navigator pour la visualisation de couverture.
- **Plugins** : extensible avec des analyzers personnalisés via le protocole `RuleAnalyzer`.

## Commandes principales

```bash
rulescope scan ./rules --top-issues 10
rulescope explain ./rules --all --max-rules 5
rulescope compare ./baseline ./candidate --fail-on-regression
rulescope report ./rules -o rulescope_report.html
rulescope maintainers ./rules
rulescope navigator ./rules -o coverage_layer.json
rulescope ci ./rules --min-score 70
rulescope console
```

## Mode français

RuleScope supporte le français nativement :

```bash
# Via variable d'environnement
export RULESCOPE_LANG=fr
rulescope scan ./rules --top-issues 5

# Via option CLI
rulescope scan ./rules --lang fr --top-issues 5

# Dans la console interactive
rulescope console
> /lang fr
```

## Pourquoi RuleScope existe

Le contenu de détection "fonctionne" souvent techniquement tout en étant coûteux à maintenir et risqué à opérer. Les problèmes typiques incluent :

- Logique à base de wildcards qui génère des faux positifs (y compris les wildcards en début de chaîne qui tuent les performances SIEM)
- Règles avec des sélecteurs faibles et une faible diversité de champs
- Détections dupliquées ou qui se chevauchent
- Tags ATT&CK manquants et hygiène des métadonnées insuffisante
- Sévérité incohérente avec le niveau de confiance
- Logique de condition référençant des sélections indéfinies ou ignorant des sélections définies
- Règles en pure négation ou filter-only qui matchent tout
- Régressions introduites pendant les pull requests

RuleScope transforme ces conversations de revue en un processus de contrôle qualité répétable.

## Démarrage rapide

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
rulescope scan ./examples/rules --top-issues 5
```

Pour le développement :

```bash
pip install -e ".[dev]"
pytest
ruff check rulescope tests
```

## Système de plugins

RuleScope supporte des analyzers personnalisés via le protocole `RuleAnalyzer` :

```python
from rulescope.analyzers.base import RuleAnalyzer
from rulescope.models.finding import Finding
from rulescope.models.rule import DetectionRule

class MonAnalyzer:
    def analyze(self, rule: DetectionRule) -> tuple[int, list[Finding]]:
        findings = []
        score = 100
        if not rule.references:
            score -= 10
            findings.append(Finding(
                code="CUSTOM-001", severity="low", category="custom",
                message="Pas de références.", recommendation="Ajouter des URLs sources.",
            ))
        return max(0, score), findings
```

Enregistrement à l'exécution ou via entry points setuptools.

## Licence

MIT
