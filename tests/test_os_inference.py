from app.os_inference import authoritative_os, infer_os_identity, os_display


def service(port: int, name: str, product: str = "") -> dict:
    return {
        "port": port,
        "protocol": "tcp",
        "service": name,
        "product": product,
    }


def test_windows_inference_uses_agreeing_service_evidence():
    host = {
        "os_group": "Unclassified",
        "ports": [
            service(135, "msrpc", "Microsoft Windows RPC"),
            service(139, "netbios-ssn", "Microsoft Windows netbios-ssn"),
            service(445, "microsoft-ds"),
        ],
    }

    inference = infer_os_identity(host)

    assert inference["family"] == "Windows"
    assert inference["confidence"] == "high"
    assert any("Microsoft Windows" in item for item in inference["evidence"])
    assert os_display({**host, "os_inference": inference}) == "Windows (inferred)"


def test_linux_inference_requires_linux_specific_fingerprint():
    assert infer_os_identity({
        "os_group": "Unclassified",
        "ports": [service(22, "ssh", "OpenSSH")],
    }) is None

    inference = infer_os_identity({
        "os_group": "Unclassified",
        "ports": [service(22, "ssh", "OpenSSH Ubuntu Linux")],
    })
    assert inference["family"] == "Linux / Unix-like"
    assert inference["confidence"] == "high"


def test_network_role_inference_is_explicit_and_non_destructive():
    inference = infer_os_identity({
        "role": "firewall",
        "vendor": "pfSense",
        "services": [],
    })
    assert inference["family"] == "Network appliance"
    assert inference["confidence"] == "high"
    assert "firewall" in inference["evidence"][0]

    authoritative = {"os": "Windows Server 2022", "ports": [service(22, "ssh", "Linux")]}
    assert authoritative_os(authoritative) == "Windows Server 2022"
    assert infer_os_identity(authoritative) is None
    assert os_display(authoritative) == "Windows Server 2022"
