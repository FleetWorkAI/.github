# Baseline OpenRouter et LiteLLM du 2026-08-05

Photographie expurgée prise à `2026-08-05T13:58:03Z`. Elle ne contient ni
secret, ni prompt, ni sortie de modèle, ni identifiant de société ou de run.

## Secrets

- La clé de gestion publiée dans la conversation a été désactivée dans
  OpenRouter. Une requête d'authentification avec cette clé rend `401`.
- Son remplacement rend `200`, expose bien `is_management_key=true` et peut
  lire les crédits. Sa valeur est stockée dans le trousseau macOS sous le
  service `fleetwork.openrouter.management`.
- La clé d'inférence FleetWork est distincte, active, plafonnée à 15 USD et
  avait consommé 0,0044791 USD lors de la photographie.
- Aucun fichier temporaire contenant la nouvelle clé de gestion n'est conservé.

## Catalogue réellement exposé

`GET https://api.dev.fleetwork.ai/v1/models` avec la clé virtuelle du runner
rend `200` et les alias suivants :

- `claude-haiku-4-5`
- `claude-opus-4-7`
- `claude-sonnet-4-6`
- `gpt-4o`
- `gpt-4o-mini`
- `gpt-5-nano`
- `text-embedding-3-small`

Les six alias de chat existent donc dans le proxy. L'embedding est une septième
route interne et ne doit pas devenir sélectionnable.

## Coûts des sept derniers jours

Agrégat PostgreSQL en lecture seule sur `run_steps`, filtré par
`COALESCE(started_at, finished_at) >= NOW() - INTERVAL '7 days'` :

| Provenance | Étapes | Coût nul | Coût absent | Total micro-USD |
| --- | ---: | ---: | ---: | ---: |
| `litellm` | 10 | 0 | 0 | 5 608 |
| `estimated` | 9 | 0 | 0 | 19 571 |

Total : 19 étapes et 25 179 micro-USD. La mesure LiteLLM couvre 52,6 % des
étapes ; 47,4 % restent estimées. Les dix-neuf étapes sont `succeeded` : une
Claude Haiku 4.5, huit GPT-4o mini et dix GPT-5 nano.

## Défauts de configuration confirmés

- `MAX_COST_MICRO_USD_PER_RUN` est absent du runner déployé. Son défaut de code
  vaut `0`, donc le plafond global est désactivé.
- `LITELLM_SPEND_API_KEY` est absent du runner déployé.
- La clé de complétion du runner obtient `401` sur `/spend/logs`, ce qui confirme
  qu'elle ne peut pas remplacer la clé de lecture dédiée.
- `LITELLM_DEFAULT_MODEL` vaut `gpt-5-nano` en production.
- Le runner conserve le `request_id` reçu dans les chunks SSE, mais ne génère
  ni ne persiste encore de `correlation_id` serveur. Un crash après émission et
  avant réponse reste donc ambigu et ne doit pas être rejoué automatiquement.
- La variable locale nommée `PROD_LITELLM_API_KEY` ne s'authentifie pas auprès
  du proxy. Les opérations ont utilisé la vraie clé virtuelle montée sur le
  runner ; le nommage local doit être corrigé sans recopier de secret.

## Coolify

Le contrôle expurgé des environnements web, worker, runner et coordinator rend
zéro doublon réel par couple `(key, is_preview)`. Les paires production/preview
sont deux scopes légitimes et ne doivent pas être supprimées. Le dry-run du
dispatcher central valide les dépôts, la branche `main`, les checks des SHA
courants et ces quatre environnements sans mutation.
