# Notes pédagogiques — TLSGuard

Ce document rassemble les notions réseau et TLS utilisées dans le projet.

## TCP et TLS

- **TCP** établit un canal de transport fiable entre deux hôtes. Il ne chiffre pas les données.
- **TLS** s'appuie généralement sur TCP pour négocier des paramètres cryptographiques, authentifier le serveur (lorsque le client vérifie son certificat) et protéger les données en transit.
- Un handshake TLS réussi prouve que les paramètres de cette connexion ont pu être négociés. Il ne prouve pas, à lui seul, que le certificat est digne de confiance ou que toute la configuration est sûre.

## API Python utilisées

### `socket.create_connection()`

Ouvre une connexion TCP vers un nom d'hôte ou une adresse IP et un port. Le paramètre `timeout` limite l'attente de chaque connexion.

### `ssl.SSLContext`

Représente la configuration TLS du client : versions autorisées, options de vérification et suites cryptographiques configurables. TLSGuard crée un contexte distinct pour chaque probe afin de tester une version ou une suite donnée sans réutiliser un état de négociation précédent.

### `wrap_socket()` et `server_hostname`

`wrap_socket()` démarre TLS sur une socket TCP existante. `server_hostname=host` permet notamment d'envoyer le nom demandé via SNI, nécessaire lorsque plusieurs sites TLS partagent la même adresse IP.

### `minimum_version` et `maximum_version`

Ces propriétés limitent les versions utilisables par un contexte. En fixant les deux à la même valeur, TLSGuard teste une version précise.

### `CERT_NONE`

Désactive la validation habituelle de la chaîne de confiance. Dans TLSGuard, ce mode sert uniquement à récupérer les données d'un certificat même s'il est expiré ou auto-signé. Il ne faut jamais en déduire que le certificat est valide ou approuvé. Un client applicatif normal doit effectuer les vérifications de confiance et de nom d'hôte.

## Pourquoi les résultats ne sont-ils pas seulement des booléens ?

Un booléen `False` ne distingue pas un refus du serveur d'un timeout, d'une erreur DNS ou d'une restriction de la bibliothèque OpenSSL locale. TLSGuard utilise donc quatre états :

- `SUPPORTED` : négociation réussie.
- `NOT_SUPPORTED` : preuve explicite de refus.
- `NOT_TESTABLE` : les paramètres locaux ou une erreur ambiguë ne permettent pas de conclure.
- `ERROR` : échec réseau ou entrée/sortie.

Cette nuance réduit les faux positifs et rend le rapport plus honnête.

## Limites à retenir

Le projet inspecte actuellement le certificat feuille et ses dates de validité, mais ne valide ni la chaîne de confiance ni la correspondance hostname/SAN. L'évaluation des suites cryptographiques utilise une liste TLS 1.2 maintenue dans le code, et non une énumération exhaustive. Le score est un indicateur pédagogique interne, pas une certification ni un score CVSS.
