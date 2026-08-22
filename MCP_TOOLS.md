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
- Flags autorisés : `\\Seen`, `\\Answered`, `\\Flagged`, `\\Deleted`, `\\Draft`.

Exemple d'appel :

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_emails","arguments":{"account_name":"principal","mailbox":"INBOX","page_size":20,"unseen":true}}}
```

Exemple MOVE :

```json
{"success":true,"data":[{"old_uid":184,"old_mailbox":"INBOX","new_uid":41,"new_mailbox":"Archive","message_id":"<id@example.com>"}],"warnings":[],"errors":[]}
```

Erreurs possibles pour chaque outil : compte/dossier/UID absent, résolution ambiguë, permission refusée, read-only, limite de taille, timeout, erreur IMAP/SMTP ou configuration spéciale manquante. Les docstrings exposées par `tools/list` précisent la permission et le caractère destructif.
