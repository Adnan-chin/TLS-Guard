# Architecture de TLSGuard

Ce document décrit le chemin d'exécution principal et le rôle de chaque module.

## Vue d'ensemble

```text
Utilisateur
   |
   v
cli.py  --------------------> affichage terminal / export JSON
   |
   v
TLSScanner.run()
   |
   +--> checks/protocols.py   --> ProtocolResult
   |
   +--> checks/certificate.py --> CertificateResult ou erreur documentée
   |
   +--> checks/ciphers.py     --> CipherResult
   |
   v
rules/engine.py
   |
   +--> rules/protocol_rules.py
   +--> rules/certificate_rules.py
   +--> rules/cipher_rules.py
   |
   v
Finding[] --> scoring.py --> SecurityScore
   |
   v
models/report.py --> ScanResult --> json_report.py
```

## Responsabilités

| Module | Responsabilité |
|---|---|
| `cli.py` | Analyse les arguments, valide les paramètres, lance le scan et affiche le résultat. |
| `scanner.py` | Orchestre les contrôles et transmet le timeout à chacun d'eux. |
| `checks/protocols.py` | Tente une négociation séparée pour TLS 1.0 à TLS 1.3. |
| `checks/ciphers.py` | Essaie individuellement les suites TLS 1.2 de la liste configurée. |
| `checks/certificate.py` | Récupère le certificat feuille et extrait ses métadonnées X.509. |
| `rules/` | Transforme les observations en constats de sécurité. |
| `scoring.py` | Calcule le score heuristique ou le marque incomplet. |
| `models/` | Définit les structures de données utilisées entre les modules. |
| `json_report.py` | Sérialise un `ScanResult` au format JSON. |

## États de résultat

Les contrôles utilisent des états explicites pour éviter de réduire toutes les situations à un booléen :

- `SUPPORTED` : la négociation demandée a réussi.
- `NOT_SUPPORTED` : le serveur a fourni un signal suffisamment explicite de refus (alerte de version TLS ou absence de suite commune).
- `NOT_TESTABLE` : les restrictions du client ou une erreur de négociation ambiguë empêchent de conclure.
- `ERROR` : erreur réseau, résolution DNS, timeout ou erreur d'entrée/sortie.

Cette distinction est particulièrement importante pour un outil d'audit : un timeout n'est pas une preuve que TLS 1.3 est désactivé.

## Gestion de l'évaluation partielle

Un échec lors de la récupération du certificat ne détruit pas les autres résultats : le scan conserve les observations déjà collectées et renseigne `certificate_error`. Le score numérique est masqué dès que le certificat ou des contrôles protocoles/chiffrements sont incomplets. Les constats déjà prouvés restent affichés.

## Ajouter un contrôle

1. Définir un modèle de résultat explicite dans `checks/`.
2. Écrire le contrôle réseau dans le module approprié et accepter le paramètre `timeout`.
3. Ajouter des tests unitaires pour le succès, le refus explicite, l'erreur ambiguë et l'erreur réseau.
4. Ajouter une règle dans `rules/` sans convertir un état `ERROR` ou `NOT_TESTABLE` en vulnérabilité.
5. Ajouter l'affichage terminal et les champs JSON si nécessaire.
6. Documenter les limites du contrôle dans `docs/METHODOLOGY.md` et le README.
