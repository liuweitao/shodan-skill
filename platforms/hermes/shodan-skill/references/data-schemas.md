# Official data schemas

Use the current official schemas instead of embedding a partial field dictionary in the Skill or CLI.

## Banner records

- Datapedia overview: <https://datapedia.shodan.io/>
- Machine-readable banner JSON Schema: <https://datapedia.shodan.io/banner.schema.json>
- Schema changelog: <https://datapedia.shodan.io/changelog.html>

Treat fields not marked required as optional, preserve unknown fields in JSON output, and consult the changelog before tightening local validation. Do not reject a Shodan response merely because Datapedia added a property after this package was released.

## Exploit records

- Exploit result specification: <https://developer.shodan.io/api/exploit-specification>
- Exploits API: <https://developer.shodan.io/api/exploits/rest>

The exploit `code` property can be large and is optional. Preserve it by default; use the CLI's explicit `--omit-code` or `--truncate-code` options only when the user requests reduced output.

## Threatnet sensor events

- Threatnet event specification: <https://developer.shodan.io/api/event-specification>

This specification describes Threatnet sensor interaction events. Do not assume that every ordinary Streaming banner follows the Threatnet event shape; select the schema that matches the documented feed and preserve unfamiliar fields.
