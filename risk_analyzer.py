"""Review suggestions, not vulnerability findings."""
REVIEW = {21:'FTP may transmit credentials without encryption.',23:'Telnet typically transmits traffic without encryption.',80:'Check whether HTTP carries sensitive data.',445:'Review SMB access controls and patching.',3389:'Review remote desktop access controls.',3306:'Review database access restrictions.',5432:'Review database access restrictions.',6379:'Review Redis authentication and access restrictions.'}


def assess_port(port, status):
    if status != 'Open':
        return 'Not assessed', 'No successful TCP connection.'
    if port in REVIEW:
        return 'Review', REVIEW[port]
    return 'Informational', 'Confirm the listener is expected and appropriately configured.'
