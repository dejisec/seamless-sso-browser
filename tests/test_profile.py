import os

from seamless_sso_browser.profile import create_firefox_profile, create_krb5_conf


class TestCreateFirefoxProfile:
    def test_creates_profile_dir_with_user_js(self, tmp_path):
        profile_dir = create_firefox_profile(tmp_path)
        user_js = os.path.join(profile_dir, "user.js")
        assert os.path.isdir(profile_dir)
        assert os.path.isfile(user_js)

    def test_user_js_contains_trusted_uris(self, tmp_path):
        profile_dir = create_firefox_profile(tmp_path)
        with open(os.path.join(profile_dir, "user.js")) as f:
            content = f.read()
        assert "autologon.microsoftazuread-sso.com" in content
        assert "aadg.windows.net.nsatc.net" in content

    def test_user_js_contains_native_gsslib(self, tmp_path):
        profile_dir = create_firefox_profile(tmp_path)
        with open(os.path.join(profile_dir, "user.js")) as f:
            content = f.read()
        assert "network.negotiate-auth.using-native-gsslib" in content
        assert "true" in content

    def test_default_useragent_is_edge(self, tmp_path):
        profile_dir = create_firefox_profile(tmp_path)
        with open(os.path.join(profile_dir, "user.js")) as f:
            content = f.read()
        assert "general.useragent.override" in content
        assert "Edg/148.0.3967.96" in content

    def test_custom_useragent(self, tmp_path):
        profile_dir = create_firefox_profile(tmp_path, useragent="CustomUA/1.0")
        with open(os.path.join(profile_dir, "user.js")) as f:
            content = f.read()
        assert "CustomUA/1.0" in content


class TestCreateKrb5Conf:
    def test_creates_conf_file(self, tmp_path):
        conf_path = create_krb5_conf(tmp_path, "domain.local")
        assert os.path.isfile(conf_path)

    def test_realm_is_uppercased(self, tmp_path):
        conf_path = create_krb5_conf(tmp_path, "corp.example.com")
        with open(conf_path) as f:
            content = f.read()
        assert "CORP.EXAMPLE.COM" in content
        assert "default_realm = CORP.EXAMPLE.COM" in content

    def test_contains_no_kdc_lookup(self, tmp_path):
        conf_path = create_krb5_conf(tmp_path, "domain.local")
        with open(conf_path) as f:
            content = f.read()
        assert "dns_lookup_realm = false" in content
        assert "dns_lookup_kdc = false" in content

    def test_realm_section(self, tmp_path):
        conf_path = create_krb5_conf(tmp_path, "domain.local")
        with open(conf_path) as f:
            content = f.read()
        assert "DOMAIN.LOCAL = {" in content
        assert "kdc = dummy" in content
