from jsscan.deps import VulnDB, clean_version, in_range, vkey, summarize_vulns

DB = VulnDB.load()


def test_clean_version_strips_min_suffix_and_junk():
    assert clean_version("3.3.1.min") == "3.3.1"
    assert clean_version("1.12.4-rc.1") == "1.12.4-rc.1"
    assert clean_version("2.18.1.") == "2.18.1"
    assert clean_version("abc") is None


def test_version_ordering_and_ranges():
    assert vkey("3.5.0") > vkey("3.4.9") > vkey("3.4.0-rc.1")
    assert vkey("1.9.0b1") < vkey("1.9.0")
    assert in_range("3.3.1", {"below": "3.5.0"})
    assert not in_range("3.5.0", {"below": "3.5.0"})
    assert in_range("2.0.0", {"atOrAbove": "1.8.0", "below": "2.1.0"})
    assert not in_range("1.7.9", {"atOrAbove": "1.8.0", "below": "2.1.0"})


def test_banner_detection_with_two_signals_is_high_confidence():
    js = '/*! jQuery v3.3.1 | (c) JS Foundation */ !function(){}();'
    d = next(x for x in DB.detect("https://x.test/jquery-3.3.1.min.js", js) if x.lib == "jquery")
    assert d.version == "3.3.1" and d.confidence >= 95 and d.vulns


def test_url_only_detection_is_lower_confidence_and_flags_conflicts():
    d = next(x for x in DB.detect("https://cdn.test/ajax/libs/moment.js/2.18.1/moment.min.js", None) if x.lib == "moment.js")
    assert d.version == "2.18.1" and d.confidence <= 60
    js = '/*! jQuery v3.6.0 | x */'
    c = next(x for x in DB.detect("https://x.test/jquery-3.3.1.min.js", js) if x.lib == "jquery")
    assert c.version == "3.6.0" and c.conflict and c.confidence <= 55


def test_patched_version_has_no_vulns():
    js = '/*! jQuery v3.7.1 | x */'
    d = next(x for x in DB.detect("https://x.test/j.js", js) if x.lib == "jquery")
    assert d.vulns == []


def test_summary_picks_highest_severity():
    d = next(x for x in DB.detect("https://x.test/j.js", '/*! jQuery v1.8.0 | x */') if x.lib == "jquery")
    s = summarize_vulns(d.vulns)
    assert s["severity"] in ("medium", "high", "critical") and s["vulns"] and s["fixed_in"]
