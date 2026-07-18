"""Tests for px.pac module — PAC file loading and evaluation."""

import codecs

from px.pac import Pac

SIMPLE_PAC = b"""
function FindProxyForURL(url, host) {
    if (host == "direct.example.com") {
        return "DIRECT";
    }
    if (host == "proxy.example.com") {
        return "PROXY proxy1.com:8080";
    }
    if (host == "multi.example.com") {
        return "PROXY proxy1.com:8080; PROXY proxy2.com:3128; DIRECT";
    }
    if (host == "socks.example.com") {
        return "SOCKS5 socks.com:1080";
    }
    return "DIRECT";
}
"""

BROKEN_PAC = b"""
this is not valid javascript {{{{
"""


class TestPacLoad:
    def test_load_from_file(self, tmp_path):
        pac_file = tmp_path / "proxy.pac"
        pac_file.write_bytes(SIMPLE_PAC)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://direct.example.com", "direct.example.com")
        assert "DIRECT" in result

    def test_load_returns_direct_for_matching_host(self, tmp_path):
        pac_file = tmp_path / "proxy.pac"
        pac_file.write_bytes(SIMPLE_PAC)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://direct.example.com", "direct.example.com")
        assert result == "DIRECT"

    def test_load_returns_proxy(self, tmp_path):
        pac_file = tmp_path / "proxy.pac"
        pac_file.write_bytes(SIMPLE_PAC)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://proxy.example.com", "proxy.example.com")
        assert "proxy1.com:8080" in result
        # PROXY prefix should be stripped
        assert "PROXY " not in result

    def test_multiple_proxies_with_direct(self, tmp_path):
        pac_file = tmp_path / "proxy.pac"
        pac_file.write_bytes(SIMPLE_PAC)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://multi.example.com", "multi.example.com")
        assert "proxy1.com:8080" in result
        assert "proxy2.com:3128" in result
        assert "DIRECT" in result
        # Semicolons should be converted to commas
        assert ";" not in result

    def test_socks5_proxy(self, tmp_path):
        pac_file = tmp_path / "proxy.pac"
        pac_file.write_bytes(SIMPLE_PAC)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://socks.example.com", "socks.example.com")
        assert "socks5://socks.com:1080" in result

    def test_unknown_host_returns_direct(self, tmp_path):
        pac_file = tmp_path / "proxy.pac"
        pac_file.write_bytes(SIMPLE_PAC)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://unknown.example.com", "unknown.example.com")
        assert result == "DIRECT"

    def test_broken_pac_returns_direct(self, tmp_path):
        pac_file = tmp_path / "broken.pac"
        pac_file.write_bytes(BROKEN_PAC)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert result == "DIRECT"

    def test_explicit_encoding_latin1(self, tmp_path):
        pac_content = 'function FindProxyForURL(url, host) { return "DIRECT"; }'.encode("latin-1")
        pac_file = tmp_path / "latin.pac"
        pac_file.write_bytes(pac_content)
        pac = Pac(str(pac_file), pac_encoding="latin-1")
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert result == "DIRECT"

    def test_wrong_explicit_encoding_returns_direct(self, tmp_path):
        # UTF-16 content but declared as UTF-8
        pac_content = 'function FindProxyForURL(url, host) { return "PROXY p:80"; }'.encode("utf-16")
        pac_file = tmp_path / "bad_enc.pac"
        pac_file.write_bytes(pac_content)
        pac = Pac(str(pac_file), pac_encoding="utf-8")
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert result == "DIRECT"


PAC_JS = 'function FindProxyForURL(url, host) {{ return "PROXY proxy.{0}:8080"; }}'


class TestPacEncodingAutoDetect:
    def test_ascii_auto_detected(self, tmp_path):
        """Pure ASCII PAC loads without explicit encoding."""
        pac_file = tmp_path / "ascii.pac"
        pac_file.write_bytes(SIMPLE_PAC)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://proxy.example.com", "proxy.example.com")
        assert "proxy1.com:8080" in result

    def test_utf8_auto_detected(self, tmp_path):
        """UTF-8 PAC with non-ASCII loads without explicit encoding."""
        pac_content = PAC_JS.format("\u00e9xample.com").encode("utf-8")
        pac_file = tmp_path / "utf8.pac"
        pac_file.write_bytes(pac_content)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert "proxy.\u00e9xample.com:8080" in result

    def test_utf8_bom_auto_detected(self, tmp_path):
        """UTF-8 BOM PAC loads without explicit encoding."""
        pac_content = codecs.BOM_UTF8 + SIMPLE_PAC
        pac_file = tmp_path / "utf8bom.pac"
        pac_file.write_bytes(pac_content)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://proxy.example.com", "proxy.example.com")
        assert "proxy1.com:8080" in result

    def test_utf16_le_bom_auto_detected(self, tmp_path):
        """UTF-16-LE BOM PAC loads without explicit encoding."""
        pac_text = PAC_JS.format("example.com")
        pac_content = codecs.BOM_UTF16_LE + pac_text.encode("utf-16-le")
        pac_file = tmp_path / "utf16le.pac"
        pac_file.write_bytes(pac_content)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert "proxy.example.com:8080" in result

    def test_utf16_be_bom_auto_detected(self, tmp_path):
        """UTF-16-BE BOM PAC loads without explicit encoding."""
        pac_text = PAC_JS.format("example.com")
        pac_content = codecs.BOM_UTF16_BE + pac_text.encode("utf-16-be")
        pac_file = tmp_path / "utf16be.pac"
        pac_file.write_bytes(pac_content)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert "proxy.example.com:8080" in result

    def test_cp1252_fallback(self, tmp_path):
        """cp1252 PAC with bytes invalid in UTF-8 loads via code page cascade."""
        # \xe9 is valid in both cp1252 and latin-1 (e-acute)
        pac_text = 'function FindProxyForURL(url, host) { /* caf\xe9 */ return "PROXY proxy.example.com:8080"; }'
        pac_file = tmp_path / "cp1252.pac"
        pac_file.write_bytes(pac_text.encode("cp1252"))
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert "proxy.example.com:8080" in result

    def test_cp1252_smart_quotes(self, tmp_path):
        """cp1252 PAC with smart quotes (0x93/0x94) in comments loads correctly."""
        # Smart quotes \x93 \x94 are in the 0x80-0x9F range where cp1252 differs from latin-1
        pac_bytes = b'function FindProxyForURL(url, host) { /* \x93test\x94 */ return "PROXY proxy.example.com:8080"; }'
        pac_file = tmp_path / "smartquotes.pac"
        pac_file.write_bytes(pac_bytes)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert "proxy.example.com:8080" in result

    def test_cp1252_euro_sign(self, tmp_path):
        """cp1252 PAC with euro sign (0x80) loads correctly."""
        pac_bytes = b'function FindProxyForURL(url, host) { /* \x80 */ return "PROXY proxy.example.com:8080"; }'
        pac_file = tmp_path / "euro.pac"
        pac_file.write_bytes(pac_bytes)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert "proxy.example.com:8080" in result

    def test_cp1251_cyrillic_fallback(self, tmp_path):
        """cp1251 Cyrillic PAC loads when bytes are invalid in cp1252 (#167)."""
        # 0x98 is undefined in cp1252 but valid in cp1251 (U+0458 CYRILLIC SMALL LETTER JE)
        pac_bytes = b'function FindProxyForURL(url, host) { /* \x98 */ return "PROXY proxy.example.com:8080"; }'
        pac_file = tmp_path / "cyrillic.pac"
        pac_file.write_bytes(pac_bytes)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert "proxy.example.com:8080" in result

    def test_latin1_final_fallback(self, tmp_path):
        """Latin-1 is the ultimate fallback when all code pages fail."""
        # Bytes 0x81 + 0x98 together: 0x81 is undefined in cp1252,
        # 0x98 is undefined in cp1251, but both are valid in latin-1
        pac_bytes = b'function FindProxyForURL(url, host) { /* \x81\x98 */ return "PROXY proxy.example.com:8080"; }'
        pac_file = tmp_path / "latin1.pac"
        pac_file.write_bytes(pac_bytes)
        pac = Pac(str(pac_file))
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert "proxy.example.com:8080" in result

    def test_explicit_encoding_overrides_auto(self, tmp_path):
        """Explicit pac_encoding bypasses auto-detection."""
        pac_content = PAC_JS.format("example.com").encode("latin-1")
        pac_file = tmp_path / "explicit.pac"
        pac_file.write_bytes(pac_content)
        pac = Pac(str(pac_file), pac_encoding="latin-1")
        assert pac.pac_encoding == "latin-1"
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert "proxy.example.com:8080" in result

    def test_empty_string_encoding_triggers_auto(self, tmp_path):
        """Empty string pac_encoding is treated as auto-detect."""
        pac_file = tmp_path / "auto.pac"
        pac_file.write_bytes(SIMPLE_PAC)
        pac = Pac(str(pac_file), pac_encoding="")
        assert pac.pac_encoding is None
        result = pac.find_proxy_for_url("http://direct.example.com", "direct.example.com")
        assert result == "DIRECT"

    def test_decode_failure_returns_direct(self, tmp_path):
        """Wrong explicit encoding falls back to DIRECT."""
        pac_content = PAC_JS.format("example.com").encode("utf-16")
        pac_file = tmp_path / "bad.pac"
        pac_file.write_bytes(pac_content)
        pac = Pac(str(pac_file), pac_encoding="ascii")
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert result == "DIRECT"


class TestPacContentTypeCharset:
    """Tests for Content-Type charset extraction and usage."""

    def test_parse_charset_simple(self):
        """Extract charset from a simple Content-Type header."""
        assert Pac._parse_content_type_charset("application/x-ns-proxy-autoconfig; charset=utf-8") == "utf-8"

    def test_parse_charset_quoted(self):
        """Extract charset when value is quoted."""
        assert Pac._parse_content_type_charset('text/html; charset="windows-1251"') == "windows-1251"

    def test_parse_charset_uppercase(self):
        """Charset key matching is case-insensitive."""
        assert Pac._parse_content_type_charset("text/html; Charset=UTF-8") == "UTF-8"

    def test_parse_charset_no_charset(self):
        """Return None when no charset is present."""
        assert Pac._parse_content_type_charset("application/x-ns-proxy-autoconfig") is None

    def test_parse_charset_none_input(self):
        """Return None for None input."""
        assert Pac._parse_content_type_charset(None) is None

    def test_parse_charset_empty_string(self):
        """Return None for empty string input."""
        assert Pac._parse_content_type_charset("") is None

    def test_parse_charset_empty_value(self):
        """Return None when charset= has no value."""
        assert Pac._parse_content_type_charset("text/html; charset=") is None

    def test_parse_charset_multiple_params(self):
        """Extract charset when other parameters are present."""
        assert Pac._parse_content_type_charset("text/html; boundary=something; charset=iso-8859-1") == "iso-8859-1"

    def test_content_type_charset_overrides_detection(self, tmp_path):
        """Content-Type charset takes priority over BOM and byte analysis."""
        # Write valid UTF-8 data but claim cp1251 via content_type
        pac_content = PAC_JS.format("example.com").encode("utf-8")
        pac_file = tmp_path / "ct.pac"
        pac_file.write_bytes(pac_content)
        pac = Pac(str(pac_file))
        # Call _detect_encoding directly with a content_type
        encoding = pac._detect_encoding(pac_content, "application/x-ns-proxy-autoconfig; charset=cp1251")
        assert encoding == "cp1251"

    def test_content_type_charset_overrides_bom(self, tmp_path):
        """Content-Type charset takes priority even when BOM is present."""
        pac_content = codecs.BOM_UTF8 + PAC_JS.format("example.com").encode("utf-8")
        pac_file = tmp_path / "bom_ct.pac"
        pac_file.write_bytes(pac_content)
        pac = Pac(str(pac_file))
        encoding = pac._detect_encoding(pac_content, "text/html; charset=ascii")
        assert encoding == "ascii"

    def test_content_type_charset_in_load(self, tmp_path):
        """Content-Type charset is used when loading PAC data via _load."""
        # Encode as cp1251, pass content_type declaring cp1251
        pac_text = 'function FindProxyForURL(url, host) { /* \u0442\u0435\u0441\u0442 */ return "PROXY proxy.example.com:8080"; }'
        pac_bytes = pac_text.encode("cp1251")
        pac_file = tmp_path / "ct_load.pac"
        pac_file.write_bytes(pac_bytes)
        pac = Pac(str(pac_file))
        # Simulate what _load_url does: call _load with content_type
        pac._load(pac_bytes, content_type="application/x-ns-proxy-autoconfig; charset=cp1251")
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert "proxy.example.com:8080" in result

    def test_explicit_encoding_overrides_content_type(self, tmp_path):
        """Explicit pac_encoding takes priority over Content-Type charset."""
        pac_content = PAC_JS.format("example.com").encode("utf-8")
        pac_file = tmp_path / "explicit_ct.pac"
        pac_file.write_bytes(pac_content)
        pac = Pac(str(pac_file), pac_encoding="utf-8")
        # Even with content_type claiming cp1251, explicit encoding wins
        pac._load(pac_content, content_type="text/html; charset=cp1251")
        result = pac.find_proxy_for_url("http://example.com", "example.com")
        assert "proxy.example.com:8080" in result

    def test_bad_content_type_charset_fails_load(self, tmp_path):
        """Invalid charset from Content-Type causes decode failure."""
        pac_content = PAC_JS.format("example.com").encode("utf-8")
        pac_file = tmp_path / "bad_ct.pac"
        pac_file.write_bytes(pac_content)
        pac = Pac(str(pac_file))
        # Call _load with bad charset — should fail and leave pac unloaded
        pac._load(pac_content, content_type="text/html; charset=not-a-real-encoding")
        assert pac.pac_find_proxy_for_url is None


class TestPacCleanup:
    def test_del_releases_resources(self, tmp_path):
        pac_file = tmp_path / "proxy.pac"
        pac_file.write_bytes(SIMPLE_PAC)
        pac = Pac(str(pac_file))
        # Force load
        pac.find_proxy_for_url("http://example.com", "example.com")
        assert pac.pac_find_proxy_for_url is not None
        pac.__del__()
        assert pac.pac_find_proxy_for_url is None

    def test_del_safe_when_not_loaded(self):
        pac = Pac("/nonexistent")
        # Should not raise
        pac.__del__()


class TestPacCallables:
    def test_dns_resolve(self, tmp_path):
        pac_file = tmp_path / "proxy.pac"
        pac_file.write_bytes(SIMPLE_PAC)
        pac = Pac(str(pac_file))
        result = pac.dnsResolve("localhost")
        assert result == "127.0.0.1"

    def test_dns_resolve_bad_host(self, tmp_path):
        pac_file = tmp_path / "proxy.pac"
        pac_file.write_bytes(SIMPLE_PAC)
        pac = Pac(str(pac_file))
        result = pac.dnsResolve("this.host.definitely.does.not.exist.invalid")
        assert result == ""

    def test_my_ip_address(self, tmp_path):
        pac_file = tmp_path / "proxy.pac"
        pac_file.write_bytes(SIMPLE_PAC)
        pac = Pac(str(pac_file))
        result = pac.myIpAddress()
        # Should return some IP address
        assert len(result) > 0
