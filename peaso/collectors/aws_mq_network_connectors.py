"""Minimal, pre-cache projection of applied ActiveMQ network connectors."""

import base64
import re
from urllib.parse import urlsplit
from xml.etree import ElementTree


_ENDPOINT = re.compile(r"(?:ssl|tcp|nio\+ssl|nio)://[^\s,()?\"<>]+", re.IGNORECASE)


def project_revision(response):
    """Keep destination host/port only; never cache broker XML or credentials."""
    if not isinstance(response, dict) or not isinstance(response.get("ConfigurationId"), str):
        raise ValueError("mq_configuration_revision_identity_missing")
    encoded = response.get("Data")
    if not isinstance(encoded, str) or len(encoded) > 2_000_000:
        raise ValueError("mq_configuration_revision_data_unavailable")
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > 1_500_000 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
            raise ValueError("mq_configuration_revision_xml_untrusted")
        root = ElementTree.fromstring(raw)
    except (ValueError, ElementTree.ParseError) as exc:
        raise ValueError("mq_configuration_revision_xml_malformed") from exc
    connectors, complete = [], True
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "networkConnector":
            continue
        uri = element.attrib.get("uri")
        matches = _ENDPOINT.findall(uri) if isinstance(uri, str) else []
        if not matches:
            complete = False
            continue
        for token in matches:
            try:
                parsed = urlsplit(token)
                host, port = parsed.hostname, parsed.port
            except ValueError:
                host, port = None, None
            if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
                complete = False
                continue
            connectors.append({"Host": host.lower(), "Port": port,
                               "Duplex": element.attrib.get("duplex", "false").lower() == "true"})
    return {"ConfigurationId": response["ConfigurationId"],
            "NetworkConnectors": sorted(connectors, key=lambda row: (row["Host"], row["Port"], row["Duplex"])),
            "ConnectorParseComplete": complete}
