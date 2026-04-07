# RuleScope Benchmark Report

**Target:** `./sigmahq_catalog/rules`

## Summary

| Metric | Value |
|--------|-------|
| Total files | 3111 |
| Parsed OK | 3111 |
| Parse failures | 0 |
| Standard rules | 3111 |
| Correlation rules | 0 |
| Filter rules | 0 |
| Parse rate | 100.0% |

## Quality

| Metric | Value |
|--------|-------|
| Average Rule Score | **94/100** |
| Catalog Health Score | **81/100** (Good) |
| Median score | 95 |
| Total findings | 13431 |
| Duplicate clusters | 268 |
| Overlap pairs | 6018 |

## Performance

| Metric | Value |
|--------|-------|
| Total time | 294304.3 ms |
| Rules/second | 10.6 |
| Time per rule | 94.6 ms |

## Score Distribution

| Range | Count | Pct |
|-------|-------|-----|
| 90-100 | 2720 | 87.4% |
| 75-89 | 390 | 12.5% |
| 50-74 | 1 | 0.0% |
| 25-49 | 0 | 0.0% |
| 0-24 | 0 | 0.0% |

## Finding Distribution by Category

| Category | Count |
|----------|-------|
| weakness | 5286 |
| documentation | 1946 |
| overlap | 1549 |
| attack | 1477 |
| duplicate | 1271 |
| noise | 1085 |
| maintainability | 494 |
| metadata | 320 |
| structural | 3 |

## Top Logsources

| Logsource | Rules |
|-----------|-------|
| windows/process_creation | 1167 |
| windows/registry_set | 204 |
| windows/file_event | 165 |
| windows/ps_script | 160 |
| windows/security | 144 |
| linux/process_creation | 119 |
| windows/image_load | 98 |
| macos/process_creation | 67 |
| windows/system | 63 |
| aws/cloudtrail | 55 |
