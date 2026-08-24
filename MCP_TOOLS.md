# Outils MCP

Tous les outils acceptent `account_name` lorsque pertinent; sans valeur, le compte actif par défaut est utilisé. Un UID est toujours scoped par compte et dossier. Toutes les réponses suivent `{success,data,warnings,errors}`; les lots peuvent ajouter `{partial,processed,failed}`.

| Groupe | Outils | Permission | Mutation |
|---|---|---|---|
| Comptes | `list_accounts`, `get_account`, `test_account` | read | non |
| Compte par défaut | `set_default_account` | admin | oui, auditée |
| Dossiers | `list_mailboxes`, `get_mailbox`, `resolve_mailbox` | read | non |
| Dossiers | `create_mailbox`, `rename_mailbox`, `subscribe_mailbox`, `unsubscribe_mailbox` | folders | oui |
| Dossiers | `delete_mailbox` | folders | **destructif** |
| Listes/recherche | `list_emails`, `search_emails` | read | non |
| Lecture | `get_email`, `get_emails`, `get_email_headers`, `get_raw_message` | read | non |
| Conversations | `get_thread`, `get_conversation` | read | non |
| Flags | `mark_read`, `mark_unread`, `add_flags`, `remove_flags`, `set_flags`, `star_email`, `unstar_email` | flags | oui |
| Déplacement | `move_email`, `move_emails`, `archive_email`, `archive_emails`, `trash_email`, `trash_emails`, `restore_email`, `restore_emails` | move | oui |
| Copie | `copy_email`, `copy_emails` | copy | oui |
| Suppression | `delete_email_permanently`, `delete_emails_permanently` | delete | **EXPUNGE destructif** |
| Brouillons | `create_draft`, `update_draft`, `send_draft` | send | oui |
| Brouillons | `delete_draft` | delete | destructif |
| SMTP | `send_email`, `reply_email`, `reply_all`, `forward_email` | send | oui, auditée |
| Pièces jointes | `list_attachments`, `download_attachment`, `save_attachment` | attachments | non |
| Facebook images | `upload_temporary_image` | facebook.write | oui, temporaire |
| Dolibarr lecture | `dolibarr_health_check`, `dolibarr_list_resources`, `dolibarr_list`, `dolibarr_get` | dolibarr.read | non |
| Dolibarr écriture | `dolibarr_create`, `dolibarr_update`, `dolibarr_action` | dolibarr.write | oui |
| Dolibarr suppression | `dolibarr_delete` | dolibarr.delete | **destructif** |
| Nextcloud fichiers | `nextcloud_health_check`, `nextcloud_list_folder`, `nextcloud_get_file_info`, `nextcloud_download_file`, `nextcloud_list_trash`, `nextcloud_list_shares`, `nextcloud_get_account_info` | nextcloud.read | non |
| Nextcloud écriture | `nextcloud_upload_file`, `nextcloud_create_folder`, `nextcloud_move`, `nextcloud_copy`, `nextcloud_restore_trash_item`, `nextcloud_create_share`, `nextcloud_update_share`, `nextcloud_update_account_field`, `nextcloud_webdav_request`, `nextcloud_ocs_request` | nextcloud.write | oui |
| Nextcloud suppression | `nextcloud_delete`, `nextcloud_delete_trash_item`, `nextcloud_delete_share` | nextcloud.delete | **destructif** (la corbeille reste souvent récupérable) |
| Telegram lecture | `telegram_health_check`, `telegram_get_updates`, `telegram_get_callback_result` | telegram.read | non |
| Telegram écriture | `telegram_send_message`, `telegram_send_report`, `telegram_send_buttons`, `telegram_set_commands` | telegram.write | oui |

## Paramètres et comportements

- Mailboxes : `mailbox` accepte un canonical name ou un libellé uniquement si la résolution est non ambiguë. Les créations/renommages utilisent un canonical name. Le delimiter n'est jamais supposé.
- Listes : `page=1`, `page_size=50` (maximum 500), `since`, `before`, `sender`, `to`, `subject`, `text`, `seen`, `flagged`, `sort=date|sender|subject`. IMAP `SUBJECT` est généralement une recherche partielle, pas `subject === valeur`.
- Lecture : `mailbox`, `uid`; les corps acceptent `offset=0`, `limit=1000000`. La source brute est base64 et limitée par `MAX_RAW_MESSAGE_SIZE_MB`.
- Lots : les formes pluriel prennent `uids: number[]` et signalent les échecs partiels.
- MOVE/COPY : `target_mailbox`; la réponse fournit `old_uid`, `old_mailbox`, `new_uid`, `new_mailbox`, `message_id`. N'utilisez plus l'ancien UID après MOVE.
- SMTP : `to`, `subject`, `text`, `html`, `cc`, `bcc`, `reply_to`, `attachments`, `headers`. Une PJ vaut `{filename,content_type,content_base64}`.
- Reply/forward : `mailbox`, `uid`, contenu et destinataires; le forward accepte `include_attachments=false`. Les réponses utilisent `In-Reply-To` et `References`; jamais le sujet seul.
- Images Facebook : pour une image jointe dans ChatGPT, appeler `upload_temporary_image` avec `image_base64`, `filename`, `mime_type` et `preserve_original=true` si les octets source doivent être conservés exactement. Réutiliser ensuite la valeur `file_id` retournée comme `temporary_file_id` dans `facebook_create_photo_post`. Le serveur fournit l'URL HTTPS publique à Meta et supprime le fichier après l'appel Facebook; l'URL expire aussi après 10 minutes. Pour un appel unique, `facebook_create_photo_post` accepte directement `image_base64` et effectue automatiquement ce même transfert temporaire.
- Le SDK MCP 2.0 utilisé par ce serveur ne fournit pas de paramètre outil natif `file`/`blob` pris en charge automatiquement par ChatGPT. Le Base64 est donc le mode de transfert compatible actuel; une URL HTTP(S) publique peut aussi être fournie directement. Les URLs locales, privées, link-local et metadata sont refusées avant l'envoi à Facebook.
- Import distant : `upload_temporary_image_from_url(image_url, filename, preserve_original=true)` télécharge une image HTTP(S), vérifie son MIME et sa signature, calcule son SHA-256 et retourne un `file_id`. Les redirections sont limitées et chaque destination est contrôlée contre les réseaux privés; une URL ChatGPT doit être testée car elle peut exiger une session.
- Pour un connecteur ChatGPT/API capable d'appeler une route multipart, l'upload binaire direct est disponible sur `POST /api/temp-media/upload` avec le champ fichier `image_file`, `preserve_original=true` et le même bearer OAuth que le MCP. La réponse contient `data.file_id`; transmettre cette valeur à `facebook_create_photo_post(temporary_file_id=...)`. Cette route n'est pas un argument MCP `FILE` natif et doit donc être déclarée séparément par le connecteur.
- La route multipart est publiée dans le schéma OpenAPI à `/openapi.json` sous l'opération `uploadTemporaryMedia`, afin de pouvoir être importée comme Action/API par un connecteur qui accepte les fichiers. Elle reste distincte des outils MCP.
- Flags autorisés : `\\Seen`, `\\Answered`, `\\Flagged`, `\\Deleted`, `\\Draft`.
- Dolibarr : le module utilise l'API REST officielle (`{DOLIBARR_API_URL}/{resource}`), authentifiée par l'en-tête `DOLAPIKEY` (jeton généré sur la fiche utilisateur Dolibarr). `dolibarr_list_resources` renvoie un catalogue indicatif de ressources courantes (`thirdparties`, `contacts`, `products`, `invoices`, `orders`, `proposals`, `contracts`, `supplierinvoices`, `supplierorders`, `projects`, `tasks`, `agendaevents`, `adherents`, `users`, `bankaccounts`, `warehouses`, `stockmovements`, `expensereports`, `interventions`, `shipments`, `documents`, `setup/dictionary`, ...), non exhaustif : tout module Dolibarr exposant une classe API (`api_<module>.class.php`) reste accessible via les mêmes outils génériques. `dolibarr_list` accepte `sqlfilters` avec la syntaxe Dolibarr (ex. `(t.email:like:'%@acme.com')`), `sortfield`, `sortorder`, `limit` (≤1000) et `page`. `dolibarr_create`/`dolibarr_update` prennent un `payload` JSON correspondant aux champs de l'objet Dolibarr. `dolibarr_action` couvre les sous-actions documentées (`validate`, `close`, `approve`, `payments`, `settopaid`, `addtimespent`, ...) via `POST /{resource}/{object_id}/{action}`. `dolibarr_delete` est destructif et respecte `DESTRUCTIVE_OPERATIONS_ENABLED`.
- Nextcloud : le module combine WebDAV (`{NEXTCLOUD_URL}/remote.php/dav/files/{user}/...` pour fichiers/dossiers, `.../dav/trashbin/{user}/...` pour la corbeille) et l'API OCS (`{NEXTCLOUD_URL}/ocs/v2.php/...` pour partages, profil et capabilities), authentifiés en Basic Auth avec un **mot de passe d'application** (jamais le mot de passe principal du compte). `nextcloud_list_folder(path, depth)` liste un dossier (`depth="1"` enfants directs, `"infinity"` récursif si le serveur l'autorise). `nextcloud_download_file`/`nextcloud_upload_file` transportent le contenu en base64 et respectent `NEXTCLOUD_MAX_DOWNLOAD_MB`/`NEXTCLOUD_MAX_UPLOAD_MB`. `nextcloud_delete` déplace normalement l'élément vers la corbeille Nextcloud, récupérable via `nextcloud_list_trash`/`nextcloud_restore_trash_item`; `nextcloud_delete_trash_item` sans argument vide toute la corbeille et est irréversible. `nextcloud_create_share`/`nextcloud_update_share`/`nextcloud_delete_share` pilotent l'API de partage officielle (utilisateur, groupe, lien public, e-mail, fédéré, cercle). `nextcloud_get_account_info`/`nextcloud_update_account_field` lisent/modifient le profil du compte configuré (quota, e-mail, nom affiché, ...). `nextcloud_webdav_request`/`nextcloud_ocs_request` sont des échappatoires génériques pour tout endpoint non couvert par un outil dédié.
- Telegram : le bot n'écoute qu'un unique chat privé (`TELEGRAM_ALLOWED_CHAT_ID`); tout message ou callback venant d'un autre `chat_id` est ignoré silencieusement (aucune réponse, aucune erreur). Un sondage (`getUpdates`) tourne en tâche de fond au démarrage du serveur et gère `/start`, `/menu`, `/rapport`, `/mails`, `/factures`, `/avalider`, `/dolibarr`, `/nextcloud`, `/status`, `/help`, ainsi que le menu principal à boutons inline et leurs callbacks. `telegram_send_buttons` sert à poser une question avec choix (ex. `🏢 LFINFO` / `👤 Personnel` / `🔀 Mixte` pour une facture ambiguë) : il renvoie un `request_id`; `telegram_get_callback_result(request_id)` renvoie `{status: "pending"|"answered", answer}` une fois que l'opérateur a tapé un bouton, pour que ChatGPT/MCP poursuive le workflow. Le jeton du bot n'apparaît jamais dans les logs ni les réponses d'erreur (toujours redacted).

Exemple d'appel :

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_emails","arguments":{"account_name":"principal","mailbox":"INBOX","page_size":20,"unseen":true}}}
```

Exemple MOVE :

```json
{"success":true,"data":[{"old_uid":184,"old_mailbox":"INBOX","new_uid":41,"new_mailbox":"Archive","message_id":"<id@example.com>"}],"warnings":[],"errors":[]}
```

Erreurs possibles pour chaque outil : compte/dossier/UID absent, résolution ambiguë, permission refusée, read-only, limite de taille, timeout, erreur IMAP/SMTP ou configuration spéciale manquante. Les docstrings exposées par `tools/list` précisent la permission et le caractère destructif.

## Private attachment hand-off

- `mail_list_attachments` lists attachments. `mail_get_attachment` retrieves one into a private server-side store and returns `temporary_file_id`, filename, MIME type, size, SHA-256, expiry, and parsed UBL data when applicable; it does not return base64.
- `mail_parse_ubl_temporary_file` parses an XML temporary file only when it is a UBL Invoice or CreditNote. Returned fields are taken from the XML; absent values remain null.
- `nextcloud_upload_temporary_file` accepts the opaque id, can create missing folders, and supports `collision=error|overwrite|rename`.
- `dolibarr_attach_temporary_file` attaches the private file to an existing object; it defaults to `supplierinvoices` and resolves the object reference server-side.
- Private files use `TEMPORARY_FILE_DIR`, `TEMPORARY_FILE_TTL_MINUTES`, and `TEMPORARY_FILE_MAX_BYTES`. They are cleaned automatically and are never publicly served. Legacy temporary media URLs require `TEMPORARY_MEDIA_PUBLIC_ENABLED=true`.