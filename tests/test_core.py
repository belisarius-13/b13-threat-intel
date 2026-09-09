from b13intel.core import application_name


def test_application_name() -> None:
    assert application_name() == "B13 Threat Intel"
