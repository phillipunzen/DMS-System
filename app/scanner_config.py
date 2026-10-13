"""Shared scanner protocol selection, including existing single-protocol accounts."""
def protocols(config):
    selected = config.get('protocols')
    if selected is None:
        selected = [config.get('protocol', 'sftp')]
    return [p for p in ('sftp', 'ftp') if p in selected]
