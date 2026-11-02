import io
import itertools
import logging

from unifi_fabric.secret_scrub import install_log_scrubber


def test_completed_log_message(monkeypatch):
    import unifi_fabric.secret_scrub as module

    synthetic = ("671902", "splitsecret")
    monkeypatch.setattr(module, "_log_secrets", lambda: synthetic)
    install_log_scrubber()
    for secret in synthetic:
        for split in range(1, len(secret)):
            for left, right in itertools.product("srd", repeat=2):
                if "d" in (left, right) and not secret.isdecimal():
                    continue
                args = [secret[:split], secret[split:]]
                if left == "d":
                    args[0] = int(args[0])
                if right == "d":
                    args[1] = int(args[1])
                record = logging.getLogger("l10.completed").makeRecord(
                    "l10.completed",
                    logging.INFO,
                    __file__,
                    1,
                    "%" + left + "%" + right,
                    tuple(args),
                    None,
                )
                stream = io.StringIO()
                logging.StreamHandler(stream).handle(record)
                assert secret not in stream.getvalue()
        record = logging.getLogger("l10.completed").makeRecord(
            "l10.completed",
            logging.INFO,
            __file__,
            1,
            "%d" if secret.isdecimal() else "%s",
            (int(secret) if secret.isdecimal() else secret,),
            None,
        )
        assert secret not in record.getMessage()


def test_access_formatter_completed_fields(monkeypatch):
    from uvicorn.logging import AccessFormatter

    import unifi_fabric.secret_scrub as module

    # Formatter-generated values must be scrubbed after args are unpacked too.
    synthetic = ("200", "GET /synthetic")
    monkeypatch.setattr(module, "_log_secrets", lambda: synthetic)
    install_log_scrubber()
    record = logging.getLogger("l10.access").makeRecord(
        "l10.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1", "GET", "/synthetic", "1.1", 200),
        None,
    )
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(AccessFormatter('%(client_addr)s "%(request_line)s" %(status_code)s'))
    handler.handle(record)
    assert not any(secret in stream.getvalue() for secret in synthetic)
