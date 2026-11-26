# Privacy metrics (LOCAL measurement, practice data)

Release: practice data, current HEAD, `RAKSHA_SECRET=practice`. Quasi-identifiers pooled per pseudonym: age interval, sex, district, PIN prefix.

| Measure | Value |
|---|---|
| pseudonymised patients | 48 |
| release equivalence classes | 40 |
| release k: minimum / median | 1 / 1 |
| release k distribution (patients) | k<=1: 33, k<=2: 45, k<=3: 48, k<=5: 48, k<=10: 48 |
| population k (register people consistent with the published QIs): minimum / median | 1 / 11 |
| population k distribution (patients) | k<=1: 2, k<=2: 4, k<=3: 5, k<=5: 7, k<=10: 21 |
| l-diversity (distinct ICD-10 categories per release class): minimum / median | 1 / 2 |

Population k is what protects a patient against the voter-list attack: a patient with population k = 1
is unique in the register on what we publish, even with every name removed.
