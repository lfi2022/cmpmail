# Home Assistant MCP

## Connection

Create a Long-Lived Access Token in the Home Assistant user profile. Configure
HOME_ASSISTANT_URL and HOME_ASSISTANT_TOKEN in .env. Optional settings are
HOME_ASSISTANT_TIMEOUT_SECONDS, HOME_ASSISTANT_VERIFY_SSL and
HOME_ASSISTANT_WEBSOCKET_MAX_SIZE_MB; see .env.example.

Use a dedicated Home Assistant account. Only grant it administrator privileges
when automation, script, scene or advanced WebSocket configuration is needed.
The token is sent only in the Authorization Bearer header and is redacted from
upstream errors.

## OAuth scopes and safety

- homeassistant.read: states, services, history, topology and registries.
- homeassistant.control: service calls, events and template rendering.
- homeassistant.admin: validation, create/update and advanced WebSocket commands.
- homeassistant.delete: delete managed automations, scripts and scenes.

READ_ONLY=true blocks control, admin and delete operations.
DESTRUCTIVE_OPERATIONS_ENABLED=false blocks homeassistant.delete. Advanced
WebSocket command types containing delete or remove also require that scope.
Existing OAuth clients need a new consent to receive newly added scopes.

## Coverage

home_assistant_list_entities with limit=0 returns the entire live state machine.
Filters can narrow results by domain, state or search text. The read-only
WebSocket query tool exposes areas, floors, labels, devices, entity registries,
config entries, panels, Lovelace, repairs and system health.

Use home_assistant_validate_automation before saving trigger, condition and
action blocks. home_assistant_set_managed_config creates or updates an
automation, script or scene and reloads its domain by default. Only UI-managed
configurations with an id can be edited through the Home Assistant config API.

home_assistant_api_get is a GET-only escape hatch below /api/.
home_assistant_websocket_command is the separately scoped administrative escape
hatch. Mutating operations are audit logged without storing tokens or bodies.

## Entity CRUD

Runtime state CRUD:

- home_assistant_create_entity creates a state-machine entity.
- home_assistant_get_entity reads its current state and attributes.
- home_assistant_update_entity replaces or merges state attributes.
- home_assistant_delete_entity removes it from the state machine.

A runtime entity is only a representation inside Home Assistant. It does not
control a physical device and may disappear after restart. Use service calls to
control devices and use a Home Assistant integration or helper for a durable
entity.

Persistent registry CRUD:

- home_assistant_get_entity_registry_entry reads registry metadata.
- home_assistant_update_entity_registry_entry updates name, entity id, area,
  icon, aliases, labels, categories, device class, visibility and options.
- home_assistant_delete_entity_registry_entry removes the registry entry.

The entity registry intentionally has no arbitrary create operation: entries are
created by integrations when they register a unique entity. Removing an entry
does not remove its physical device, and the integration can recreate it.
