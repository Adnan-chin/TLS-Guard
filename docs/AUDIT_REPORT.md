# Rapport de correction de l'archive TLSGuard

## Résumé

L'archive initiale contenait une base fonctionnelle, mais plusieurs défauts pouvaient provoquer un échec du CLI, des conclusions de scan trop catégoriques ou un rapport de sécurité trompeur. Les corrections ci-dessous ont été intégrées au projet.

## Problèmes constatés et corrections

| Priorité | Problème initial | Correction |
|---|---|---|
| Bloquant | `cli.py` transmettait `timeout` au constructeur `TLSScanner`, dont la signature ne l'acceptait pas. | Le scanner et les trois familles de contrôles acceptent et transmettent maintenant le timeout. |
| Élevée | Les erreurs DNS, timeout et certains échecs TLS étaient présentés comme une preuve de non-support. | Ajout d'états distincts `SUPPORTED`, `NOT_SUPPORTED`, `NOT_TESTABLE` et `ERROR`. Les règles de sécurité utilisent ces états de façon conservatrice. |
| Élevée | L'absence de certificat pouvait interrompre l'ensemble du scan et empêcher de conserver les autres résultats. | Le scan conserve les contrôles terminés et renseigne `certificate_error` si le certificat n'a pas pu être récupéré. |
| Élevée | L'absence de constat pouvait produire un score de 100 même si des vérifications n'avaient pas pu être faites. | Le score est maintenant `null` / `INCOMPLETE` dès que les contrôles requis ne sont pas complets. |
| Moyenne | Le statut de certificat `VALID` pouvait laisser croire que la chaîne et le nom d'hôte étaient vérifiés. | Le CLI affiche explicitement l'état de validité des dates et indique que la chaîne et le hostname ne sont pas vérifiés. |
| Moyenne | Certains noms de suites AES-SHA pouvaient être classés `UNKNOWN` alors qu'ils représentent des suites CBC historiques ; plusieurs suites pouvaient aussi générer des constats répétés avec le même identifiant. | Amélioration de la classification et regroupement des suites par catégorie dans un constat unique. |
| Moyenne | Les tests étaient rangés sous le paquet applicatif et leur import dépendait de l'environnement. | Déplacement dans `tests/` et configuration `pythonpath` / `testpaths` dans `pyproject.toml`. |
| Moyenne | Le fichier README ne décrivait que le projet de façon très sommaire. | Ajout du guide d'installation Windows, des exemples CLI, de la structure du projet et des limites. |
| Moyenne | Le CLI pouvait renvoyer un code de succès même si les vérifications étaient incomplètes. | Le CLI affiche un message explicite, enregistre le rapport partiel si demandé et renvoie un code non nul. |
| Faible | L'archive comprenait un `.venv`, des caches et des métadonnées locaux. | Exclusion de ces éléments de l'archive livrée et ajout de règles `.gitignore`. |

## Vérifications effectuées

Environnement de vérification : Python 3.13.5 dans un environnement Linux de test.

- `python -m pytest -q` : **38 tests réussis**.
- `python -m compileall -q src tests` : réussi.
- `python -m tlsguard --help` : réussi après installation éditable.
- `tlsguard --help` : réussi.
- Construction d'un wheel avec `pip wheel . --no-deps --no-build-isolation` : réussie.

## Vérifications non effectuées

- Le scan réseau complet d'un serveur public n'a pas été validé dans cet environnement. Une tentative avec un nom DNS réservé aux tests a été bloquée au niveau de la résolution DNS dans l'environnement d'exécution.
- L'exécution native sous Windows / PowerShell n'a pas été effectuée depuis cet environnement Linux. Les commandes Windows sont documentées dans le README, mais une validation finale sur la machine Windows du projet reste recommandée.

## Limites restantes

- Le timeout s'applique à chaque connexion socket ; la résolution DNS du système peut dépasser cette durée.
- Le scan des chiffrements couvre une liste maintenue de suites TLS 1.2, pas toutes les suites possibles ni les suites TLS 1.3.
- La récupération du certificat n'effectue pas la validation de la chaîne, du nom d'hôte ou de la révocation.
- Le score reste une heuristique éducative, pas une certification ni une évaluation de conformité.
