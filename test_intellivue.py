import intellivue

def test_basic_roapdus_parsing():
    data = "\x00\x01\x00\x00"  # PIPG-291

    r = intellivue.ROapdus()
    r.dissect(data)

    assert r.ro_type == intellivue.ROIV_APDU
