from whydrop.measure.direction import Echo, OutageTotals, outage_totals, packet_direction


def test_direction_down():  # echo 12 says seq 11 (bit0) missing, seq 10 (bit1) received → echo lost on the way down
    assert packet_direction(10, [Echo(12, 0, 1, 0b10)]) == "down"


def test_direction_up():
    assert packet_direction(10, [Echo(12, 0, 1, 0b01)]) == "up"


def test_direction_uses_first_later_echo_in_range():
    assert packet_direction(10, [Echo(9, 0, 1, 0), Echo(11, 0, 1, 0b1), Echo(12, 0, 1, 0)]) == "down"


def test_direction_unknown_too_far():
    assert packet_direction(10, [Echo(50, 0, 1, 0xFFFFFFFF)]) == "unknown"
    assert packet_direction(10, []) == "unknown"


def test_direction_edge_32_behind():
    assert packet_direction(10, [Echo(42, 0, 1, 1 << 31)]) == "down"


def test_totals():
    assert outage_totals(Echo(100, 90, 1, 0), Echo(110, 96, 1, 0), 3) == OutageTotals(4, 3, "ok")


def test_totals_epoch_change():
    assert outage_totals(Echo(1, 1, 1, 0), Echo(9, 3, 2, 0), 1).status == "unknown"


def test_totals_rc_went_backwards():
    assert outage_totals(Echo(1, 5, 1, 0), Echo(9, 3, 1, 0), 1).status == "unknown"


def test_totals_all_up_lost():
    assert outage_totals(Echo(1, 1, 1, 0), Echo(9, 2, 1, 0), 1) == OutageTotals(7, None, "down_unmeasurable")


def test_totals_no_gap():
    assert outage_totals(Echo(1, 1, 1, 0), Echo(2, 2, 1, 0), 1) == OutageTotals(0, 0, "ok")


def test_totals_inconsistent_counters_unknown():
    assert outage_totals(Echo(1, 1, 1, 0), Echo(9, 1, 1, 0), 0).status == "unknown"   # b not counted
    assert outage_totals(Echo(1, 1, 1, 0), Echo(9, 4, 1, 0), 5).status == "unknown"   # more echoes than arrivals
