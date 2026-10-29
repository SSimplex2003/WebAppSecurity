import logging

audit = logging.getLogger("audit")

if not audit.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s AUDIT %(message)s"))
    audit.addHandler(_handler)
    audit.setLevel(logging.INFO)
    audit.propagate = False
