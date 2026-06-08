"""Maven ``settings.xml`` — server credentials in ``<servers>`` block.

Found at ``~/.m2/settings.xml`` (user-level) and
``$M2_HOME/conf/settings.xml`` (system). Build servers and
developer workstations almost always carry Nexus / Artifactory /
Sonatype credentials here.

    <settings>
      <servers>
        <server>
          <id>nexus-releases</id>
          <username>deployer</username>
          <password>secret123</password>
        </server>
      </servers>
    </settings>

The ``<password>`` field is often a literal credential. Maven
supports encrypted passwords (``{...}`` format) which we surface
verbatim — they're still high-signal because the matching
``settings-security.xml`` master key is usually nearby.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField


def register(reg) -> None:
    # Maven settings.xml is ambiguous by name — distinguish by content
    # in the parser. The dispatch matcher is permissive; we'll
    # parse-and-yield-nothing if the XML doesn't have <servers>.
    reg(r"^settings\.xml$", parse_maven_settings)


def parse_maven_settings(content: str) -> Iterable[ExtractedField]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return

    # The XML may have an xmlns; ElementTree puts it as {ns}tag.
    # We match by local-name, ignoring the namespace.
    def _local(el):
        tag = el.tag
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    # Walk to find <servers>/<server>/<password>.
    for elem in root.iter():
        if _local(elem) != "server":
            continue
        server_id = None
        username = None
        password = None
        for child in elem:
            name = _local(child)
            text = (child.text or "").strip()
            if name == "id":
                server_id = text
            elif name == "username":
                username = text
            elif name == "password":
                password = text
        scope = server_id or "unknown_server"
        if username:
            yield ExtractedField(
                field_name=f"{scope}.username",
                value=username,
                confidence=0.7,
                parser="maven_settings_xml",
            )
        if password:
            yield ExtractedField(
                field_name=f"{scope}.password",
                value=password,
                confidence=0.95,
                parser="maven_settings_xml",
            )
