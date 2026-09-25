from app.ip_sort import ip_sort_key


def test_ip_sort_key_orders_ipv4_addresses_numerically():
    values = ["10.0.0.110", "10.0.0.11", "10.0.0.2", "10.0.0.1"]
    assert sorted(values, key=ip_sort_key) == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.11",
        "10.0.0.110",
    ]


def test_ip_sort_key_handles_ipv6_cidr_and_non_ip_labels():
    values = ["unknown", "2001:db8::10", "10.0.0.2/24", "2001:db8::2", "10.0.0.1/24"]
    assert sorted(values, key=ip_sort_key) == [
        "10.0.0.1/24",
        "10.0.0.2/24",
        "2001:db8::2",
        "2001:db8::10",
        "unknown",
    ]


def test_ip_sort_key_accepts_canonical_host_keys():
    values = ["ip:10.0.0.20", "ip:10.0.0.3"]
    assert sorted(values, key=ip_sort_key) == ["ip:10.0.0.3", "ip:10.0.0.20"]
