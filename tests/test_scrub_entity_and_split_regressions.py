import random

import pytest

from unifi_fabric.secret_scrub import scrub, scrub_bytes


@pytest.mark.parametrize("layers", range(1, 4))
@pytest.mark.parametrize("digits", range(1, 10))
@pytest.mark.parametrize("hexadecimal", [False, True])
def test_amp_numeric_entities(digits, hexadecimal, layers):
    unit = ("#x" if hexadecimal else "#") + "0" * (digits - 1) + "9;"
    text = "&" + "amp;" * layers + unit + "K!"
    assert scrub(text, ["K"]) == text[:-2] + "***!"
    assert scrub_bytes(text.encode(), ["K"]) == (text[:-2] + "***!").encode()


def test_arbitrary_input_never_raises():
    rng = random.Random(361)  # noqa: S311 - deterministic fuzz inputs
    alphabet = "%&;#ampuxU\\0123456789ABCDEFxyz\ud800"
    for _ in range(1000):
        text = "".join(rng.choices(alphabet, k=rng.randrange(150)))
        scrub(text, ["K"])
        scrub_bytes(text.encode("utf-8", "surrogatepass"), ["K"])


async def test_numeric_entities_client_log_audit(monkeypatch, tmp_path):
    import logging

    import httpx

    import unifi_fabric.secret_scrub as module
    from unifi_fabric.audit import AuditSink
    from unifi_fabric.client import UniFiClient, UniFiConnectionError
    from unifi_fabric.config import Settings

    text = "&amp;#9;K!"
    settings = Settings(api_key="K")

    async def get_client(self, key_config):
        return httpx.AsyncClient(
            base_url="https://api.ui.com",
            transport=httpx.MockTransport(lambda request: httpx.Response(500, text=text)),
        )

    monkeypatch.setattr(UniFiClient, "_get_client", get_client)
    with pytest.raises(UniFiConnectionError) as exc:
        await UniFiClient(settings).request("GET", "/v1/hosts")
    assert "K!" not in str(exc.value)
    monkeypatch.setattr(module, "_log_secrets", lambda: ("K",))
    module.install_log_scrubber()
    record = logging.getLogger("l10.numeric").makeRecord(
        "l10.numeric",
        logging.INFO,
        __file__,
        1,
        "%s",
        (text,),
        None,
    )
    assert "K!" not in record.getMessage()
    path = tmp_path / "audit.log"
    sink = AuditSink(path=str(path), fmt="text", secrets=("K",))
    sink.record(method="POST", path="/synthetic", outcome="refused", status=500, reason=text)
    assert "K!" not in path.read_text()
