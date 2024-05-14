from .association import AssocReqUserData, MDSEUserInfoStd


def test_trivial_construction():
    AssocReqUserData()


def test_empty_length():
    p = AssocReqUserData()
    p = AssocReqUserData(p.build())

    assert p.ASNLength == len(MDSEUserInfoStd())
