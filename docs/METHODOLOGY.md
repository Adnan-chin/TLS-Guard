# Méthodologie et limites de sécurité

## 1. Versions TLS

TLSGuard force successivement la version minimale et maximale du contexte client à TLS 1.0, TLS 1.1, TLS 1.2 ou TLS 1.3. Une négociation réussie prouve que le serveur a accepté cette version pour cette connexion.

Un échec de handshake générique ne prouve pas que la version est désactivée. Il peut provenir d'une restriction OpenSSL locale, d'une suite cryptographique incompatible, d'une politique du serveur, d'un certificat ou d'une interruption réseau. TLSGuard ne conclut `NOT_SUPPORTED` que lorsque le refus de version est suffisamment explicite ; sinon le résultat est `NOT_TESTABLE` ou `ERROR`.

Pour TLS 1.0 et 1.1, le contexte client tente d'abaisser le niveau de sécurité OpenSSL local à `SECLEVEL=0` uniquement pour ce test. Cela ne modifie pas la politique OpenSSL globale du système.

## 2. Suites cryptographiques

Le scanner teste une liste fixe de suites TLS 1.2 dans `TLS12_CIPHERS_TO_TEST`. Chaque suite est configurée seule dans le contexte client. Le résultat `SUPPORTED` signifie qu'une négociation TLS 1.2 a réellement utilisé la suite demandée.

La classification par nom est heuristique :

- `WEAK` : suites utilisant notamment NULL, anonymous, export, RC4, DES/3DES, RC2 ou MD5.
- `LEGACY` : suites CBC et suites RSA statiques de la liste reconnue.
- `MODERN` : suites AEAD GCM ou ChaCha20-Poly1305.
- `UNKNOWN` : le nom ne correspond pas aux règles actuelles.

La liste n'est pas exhaustive. Une suite indisponible dans l'OpenSSL local est `NOT_TESTABLE`, pas `NOT_SUPPORTED`. Les suites TLS 1.3 ne sont pas encore sondées.

## 3. Certificat X.509

Le scanner récupère le certificat feuille présenté pendant une connexion TLS, puis extrait son sujet, son émetteur, son numéro de série, ses SAN DNS, son empreinte d'algorithme de signature et ses dates de validité.

La vérification de confiance est désactivée pendant cette récupération afin de pouvoir analyser un certificat expiré ou auto-signé. Par conséquent, le projet ne vérifie pas actuellement :

- la chaîne de certification et les autorités de confiance ;
- la correspondance entre le nom d'hôte demandé et les SAN ;
- la révocation (CRL/OCSP) ;
- les politiques de transparence des certificats.

`DATE_VALID` signifie uniquement que la période `notBefore` / `notAfter` est valide à l'instant du scan. Ce n'est pas une affirmation que le certificat est digne de confiance.

## 4. Score

Le score commence à 100 et soustrait les pénalités associées aux constats. Les seuils et pénalités sont des choix de conception pédagogiques. Ils ne représentent pas une norme, une certification, un CVSS officiel ou une mesure statistique du risque.

Le score est `null` dans le JSON et `NOT AVAILABLE` dans le terminal si les contrôles requis sont incomplets. Cela évite de présenter une absence de données comme un résultat parfait.

## 5. Usage responsable

Exécuter TLSGuard uniquement sur une infrastructure possédée ou explicitement autorisée. Les tests établissent des connexions TLS répétées et peuvent produire des journaux côté serveur. Ils ne doivent pas être utilisés pour provoquer une indisponibilité ou contourner des contrôles d'accès.

## 6. Améliorations possibles

- Vérification indépendante de la chaîne et du nom d'hôte.
- Énumération plus large des suites via une méthode adaptée à la version d'OpenSSL.
- Prise en charge des suites TLS 1.3.
- Export HTML avec résumé et détails des constats.
- Tests d'intégration avec un serveur TLS local aux configurations contrôlées.
- Référencement des recommandations à des versions précises des guides de durcissement.


## 7. Timeout et résolution DNS

Le paramètre `--timeout` est transmis à chaque connexion socket TCP/TLS. La résolution DNS est effectuée par le résolveur du système avant l'établissement de la socket ; la bibliothèque standard Python ne permet pas de garantir que cette opération respecte la même limite. Le timeout n'est donc ni un timeout global du scan ni une borne stricte de la durée de résolution DNS.
