import ast
import builtins
import inspect
import pathlib

import pytest

from seamless_sso_browser import errors

# (type name, base class names in declaration order, exit_code) — the published
# hierarchy contract. Names, not classes, so a missing type fails the test that
# asserts it rather than erroring at collection time.
HIERARCHY = [
    ("SsoError", ("Exception",), 1),
    ("UsageError", ("SsoError", "ValueError"), 2),
    ("TicketError", ("SsoError", "ValueError"), 3),
    ("KdcUnreachableError", ("SsoError", "OSError"), 4),
    ("KdcProtocolError", ("SsoError",), 5),
    ("LocalEnvironmentError", ("SsoError",), 1),
]


def _named_type(name: str) -> type:
    if hasattr(errors, name):
        return getattr(errors, name)
    return getattr(builtins, name)


class TestExitCodes:
    @pytest.mark.parametrize(
        "name,expected",
        [
            ("EXIT_OK", 0),
            ("EXIT_ENVIRONMENT", 1),
            ("EXIT_USAGE", 2),
            ("EXIT_TICKET", 3),
            ("EXIT_KDC_UNREACHABLE", 4),
            ("EXIT_KDC_PROTOCOL", 5),
            ("EXIT_INTERRUPTED", 130),
        ],
    )
    def test_exit_code_has_its_documented_value(self, name, expected):
        assert getattr(errors, name) == expected


class TestExceptionHierarchy:
    @pytest.mark.parametrize("name,base_names,exit_code", HIERARCHY)
    def test_bases_are_exactly_these_in_declaration_order(self, name, base_names, exit_code):
        cls = getattr(errors, name)
        expected = tuple(_named_type(base) for base in base_names)
        assert cls.__bases__ == expected

    @pytest.mark.parametrize("name,base_names,exit_code", HIERARCHY)
    def test_exit_code_reads_off_the_class(self, name, base_names, exit_code):
        assert getattr(errors, name).exit_code == exit_code

    @pytest.mark.parametrize("name,base_names,exit_code", HIERARCHY)
    def test_exit_code_reads_off_an_instance(self, name, base_names, exit_code):
        assert getattr(errors, name)("some message").exit_code == exit_code

    @pytest.mark.parametrize("name,base_names,exit_code", HIERARCHY)
    def test_every_type_is_an_sso_error(self, name, base_names, exit_code):
        assert issubclass(getattr(errors, name), errors.SsoError)

    @pytest.mark.parametrize("name", ["UsageError", "TicketError"])
    def test_usage_and_ticket_errors_are_value_errors(self, name):
        # kerberos.py's pinned pytest.raises(ValueError) contracts stay green only
        # while these two remain ValueErrors.
        assert issubclass(getattr(errors, name), ValueError)

    def test_kdc_unreachable_error_is_an_os_error(self):
        assert issubclass(errors.KdcUnreachableError, OSError)

    @pytest.mark.parametrize("name", ["KdcProtocolError", "LocalEnvironmentError"])
    def test_plain_sso_errors_are_not_value_errors_or_os_errors(self, name):
        cls = getattr(errors, name)
        assert not issubclass(cls, ValueError)
        assert not issubclass(cls, OSError)


class TestMessageRoundTrip:
    @pytest.mark.parametrize("name,base_names,exit_code", HIERARCHY)
    @pytest.mark.parametrize(
        "message",
        [
            "some distinctive message",
            # A colon and a number are the shape that would expose OSError's
            # "[Errno n] text" reformatting on KdcUnreachableError.
            "could not reach the KDC at 127.0.0.1:88 (connection refused)",
            "Invalid SID format: S-1-5-21",
        ],
    )
    def test_str_is_exactly_the_message_arg(self, name, base_names, exit_code, message):
        assert str(getattr(errors, name)(message)) == message

    @pytest.mark.parametrize("name,base_names,exit_code", HIERARCHY)
    def test_args_hold_the_single_message(self, name, base_names, exit_code):
        assert getattr(errors, name)("one message").args == ("one message",)


class TestKdcProtocolErrorFacts:
    def test_code_and_code_name_default_to_none(self):
        err = errors.KdcProtocolError("the KDC rejected the request")
        assert err.code is None
        assert err.code_name is None

    def test_code_and_code_name_are_readable_off_the_instance(self):
        err = errors.KdcProtocolError(
            "the KDC does not know that service principal",
            code=7,
            code_name="KDC_ERR_S_PRINCIPAL_UNKNOWN",
        )
        assert err.code == 7
        assert err.code_name == "KDC_ERR_S_PRINCIPAL_UNKNOWN"

    def test_str_is_unchanged_by_the_extra_facts(self):
        message = "the KDC does not know that service principal"
        err = errors.KdcProtocolError(message, code=7, code_name="KDC_ERR_S_PRINCIPAL_UNKNOWN")
        assert str(err) == message

    def test_code_and_code_name_are_keyword_only(self):
        with pytest.raises(TypeError):
            errors.KdcProtocolError("a message", 7)


# (constant name, its terms) — the negative half of the IdP messaging contract,
# one row per register. Pinned here because the register table is the contract;
# errors.py is the only place in the source the lists live.
FORBIDDEN_BY_REGISTER = [
    ("AZURE_FORBIDDEN_TERMS", ("Okta",)),
    ("OKTA_FORBIDDEN_TERMS", ("Seamless SSO", "AZUREADSSOACC$")),
    ("NEUTRAL_FORBIDDEN_TERMS", ("Okta", "Seamless SSO", "AZUREADSSOACC$")),
]


class TestForbiddenTerms:
    @pytest.mark.parametrize("name,expected", FORBIDDEN_BY_REGISTER)
    def test_register_holds_exactly_its_contract_terms(self, name, expected):
        assert getattr(errors, name) == expected

    def test_idp_values_are_the_two_the_cli_flag_takes(self):
        assert (errors.IDP_AZURE, errors.IDP_OKTA) == ("azure", "okta")

    def test_azure_gets_the_azure_terms(self):
        assert errors.forbidden_terms(errors.IDP_AZURE) == errors.AZURE_FORBIDDEN_TERMS

    def test_okta_gets_the_okta_terms(self):
        assert errors.forbidden_terms(errors.IDP_OKTA) == errors.OKTA_FORBIDDEN_TERMS

    def test_none_gets_the_neutral_terms(self):
        # A message that does not depend on the IdP must name neither vendor.
        assert errors.forbidden_terms(None) == errors.NEUTRAL_FORBIDDEN_TERMS

    @pytest.mark.parametrize("value", ["ping-federate", "Azure", "OKTA", "", "azure "])
    def test_unrecognised_value_fails_closed_to_the_neutral_terms(self, value):
        # A typo or a future third IdP gets the strictest list, never an empty one.
        assert errors.forbidden_terms(value) == errors.NEUTRAL_FORBIDDEN_TERMS


SPN_UNKNOWN = "KDC_ERR_S_PRINCIPAL_UNKNOWN"

# (code_name, its RFC 4120 code, substrings that make the message actionable) —
# the four mapped rows whose wording does not depend on the IdP.
NEUTRAL_KDC_ROWS = [
    ("KDC_ERR_WRONG_REALM", 68, ["--domain"]),
    (
        "KDC_ERR_PREAUTH_FAILED",
        24,
        ["--password", "--user-password-hash", "--user-aes-key"],
    ),
    ("KDC_ERR_C_PRINCIPAL_UNKNOWN", 6, ["--user"]),
    ("KRB_AP_ERR_SKEW", 37, ["5 minutes"]),
]


class TestKdcErrorMessage:
    @pytest.mark.parametrize("idp", [errors.IDP_AZURE, errors.IDP_OKTA])
    @pytest.mark.parametrize("code_name,code,expected", NEUTRAL_KDC_ROWS)
    def test_mapped_row_names_the_facts_that_make_it_actionable(
        self, code_name, code, expected, idp
    ):
        message = errors.kdc_error_message(code, idp, code_name=code_name)
        missing = [substring for substring in expected if substring not in message]
        assert not missing, f"{code_name} for {idp} does not name {missing}: {message!r}"

    @pytest.mark.parametrize("code_name,code,expected", NEUTRAL_KDC_ROWS)
    def test_neutral_row_is_one_string_for_both_registers(self, code_name, code, expected):
        assert errors.kdc_error_message(code, errors.IDP_AZURE, code_name=code_name) == (
            errors.kdc_error_message(code, errors.IDP_OKTA, code_name=code_name)
        )

    def test_spn_unknown_names_the_azure_sso_account_for_azure(self):
        message = errors.kdc_error_message(7, errors.IDP_AZURE, code_name=SPN_UNKNOWN)
        assert "AZUREADSSOACC$" in message

    def test_spn_unknown_names_the_supplied_okta_spn(self):
        message = errors.kdc_error_message(
            7,
            errors.IDP_OKTA,
            code_name=SPN_UNKNOWN,
            okta_spn="HTTP/acme.kerberos.okta.com",
        )
        assert "HTTP/acme.kerberos.okta.com" in message

    def test_spn_unknown_names_the_spn_shape_when_the_spn_is_unknown(self):
        message = errors.kdc_error_message(
            7,
            errors.IDP_OKTA,
            code_name=SPN_UNKNOWN,
            okta_spn=None,
        )
        assert ".kerberos." in message
        assert "--okta-org" in message

    def test_spn_unknown_is_the_row_where_the_two_registers_differ(self):
        azure = errors.kdc_error_message(7, errors.IDP_AZURE, code_name=SPN_UNKNOWN)
        okta = errors.kdc_error_message(7, errors.IDP_OKTA, code_name=SPN_UNKNOWN)
        assert azure != okta

    def test_unmapped_code_name_carries_the_name_and_the_detail(self):
        message = errors.kdc_error_message(
            201,
            errors.IDP_AZURE,
            code_name="KDC_ERR_NEVER_HEARD_OF_IT",
            detail="Something impacket described",
        )
        assert "KDC_ERR_NEVER_HEARD_OF_IT" in message
        assert "Something impacket described" in message

    def test_unmapped_code_name_without_a_detail_has_no_dangling_separator(self):
        message = errors.kdc_error_message(201, errors.IDP_AZURE, code_name="KDC_ERR_X")
        assert "KDC_ERR_X" in message
        assert not message.rstrip().endswith((":", "-", ";"))

    def test_missing_code_name_falls_back_to_the_numeric_code(self):
        message = errors.kdc_error_message(201, errors.IDP_AZURE, code_name=None)
        assert "201" in message

    @pytest.mark.parametrize("idp", [errors.IDP_AZURE, errors.IDP_OKTA, "ping-federate"])
    @pytest.mark.parametrize("code_name", [None, "", "KDC_ERR_NEVER_HEARD_OF_IT", "68"])
    def test_no_code_name_can_make_the_lookup_raise(self, code_name, idp):
        # A KeyError here would be a traceback raised by the error handler itself,
        # which is the failure this catalogue exists to remove.
        assert isinstance(errors.kdc_error_message(0, idp, code_name=code_name), str)

    def test_everything_past_the_idp_is_keyword_only(self):
        with pytest.raises(TypeError):
            errors.kdc_error_message(68, errors.IDP_AZURE, "KDC_ERR_WRONG_REALM")


class TestInterruptedMessage:
    def test_it_says_the_interruption_came_before_firefox_launched(self):
        # Ctrl+C *while* Firefox runs is a different path that stays exit 0, so
        # this text must not claim the session was aborted in general.
        assert "before Firefox launched" in errors.interrupted_message()

    def test_it_says_nothing_was_left_running(self):
        message = errors.interrupted_message()
        assert "nothing" in message.lower()
        assert "running" in message


class TestUnexpectedFailureMessage:
    @pytest.mark.parametrize(
        "marker",
        [
            "MARKER-2f9c-do-not-leak",
            # Shaped like key material: impacket's internals can surface a key in
            # an exception message, and this is the one handler that sees them.
            "a" * 32,
        ],
    )
    def test_the_exceptions_own_message_never_reaches_the_terminal(self, marker):
        message = errors.unexpected_failure_message(ValueError(marker))
        assert marker not in message

    def test_neither_str_nor_repr_of_the_exception_appears(self):
        exc = ValueError("MARKER-2f9c-do-not-leak")
        message = errors.unexpected_failure_message(exc)
        assert str(exc) not in message
        assert repr(exc) not in message

    def test_it_names_the_exception_class(self):
        message = errors.unexpected_failure_message(ValueError("MARKER-2f9c-do-not-leak"))
        assert "ValueError" in message

    def test_it_points_at_verbose_for_the_traceback(self):
        message = errors.unexpected_failure_message(ValueError("MARKER-2f9c-do-not-leak"))
        assert "--verbose" in message

    @pytest.mark.parametrize(
        "exc",
        [OSError("MARKER-2f9c"), KeyboardInterrupt(), RuntimeError("MARKER-2f9c")],
    )
    def test_any_base_exception_is_accepted_and_named(self, exc):
        assert type(exc).__name__ in errors.unexpected_failure_message(exc)


class TestTicketKindMessage:
    def test_it_names_the_spn_found_and_the_kind_expected(self):
        message = errors.ticket_kind_message(
            "krbtgt/EXAMPLE.LOCAL",
            expected="a service ticket for one of the SSO service principals",
        )
        assert "krbtgt/EXAMPLE.LOCAL" in message
        assert "a service ticket for one of the SSO service principals" in message

    def test_the_expected_kind_is_keyword_only(self):
        with pytest.raises(TypeError):
            errors.ticket_kind_message("krbtgt/EXAMPLE.LOCAL", "a service ticket")


class TestHexFormatMessage:
    def test_it_names_the_flag_the_acceptable_lengths_and_the_length_given(self):
        message = errors.hex_format_message(
            "--adssoacc-ntlm",
            expected_lengths=(32, 64),
            got_length=31,
        )
        assert "--adssoacc-ntlm" in message
        assert "32" in message
        assert "64" in message
        assert "31" in message

    def test_one_acceptable_length_reads_as_that_length(self):
        message = errors.hex_format_message(
            "--user-aes-key",
            expected_lengths=(64,),
            got_length=9,
        )
        assert "64" in message
        assert "9" in message

    def test_it_has_no_parameter_that_could_carry_the_value(self):
        # The value is a key and terminal scrollback outlives the process, so the
        # signature taking a length is what keeps the key out of it.
        params = inspect.signature(errors.hex_format_message).parameters
        assert set(params) == {"flag", "expected_lengths", "got_length"}

    def test_the_lengths_are_keyword_only(self):
        with pytest.raises(TypeError):
            errors.hex_format_message("--user-aes-key", (64,), 9)


class TestSidFormatMessage:
    def test_it_is_the_sentence_the_umbrella_pins(self):
        assert errors.sid_format_message(got="NOT-A-SID") == (
            "--user-sid must look like S-1-5-21-<a>-<b>-<c>-<rid>; got 'NOT-A-SID'."
        )

    def test_the_value_is_keyword_only(self):
        with pytest.raises(TypeError):
            errors.sid_format_message("NOT-A-SID")


class TestNtlmHashFormatMessage:
    def test_it_names_the_flag_the_required_shape_and_the_length_given(self):
        message = errors.ntlm_hash_format_message("--user-password-hash", got_length=5)
        assert "--user-password-hash" in message
        assert "[LMHASH:]NTHASH" in message
        assert "32" in message
        assert "5" in message

    def test_it_has_no_parameter_that_could_carry_the_value(self):
        # --user-password-hash carries key material, so the signature taking a
        # length is what keeps the hash out of the terminal scrollback.
        params = inspect.signature(errors.ntlm_hash_format_message).parameters
        assert set(params) == {"flag", "got_length"}

    def test_the_length_is_keyword_only(self):
        with pytest.raises(TypeError):
            errors.ntlm_hash_format_message("--user-password-hash", 5)


class TestFlagRequiresOktaIdpMessage:
    def test_it_names_the_flag_and_the_flag_that_fixes_it(self):
        message = errors.flag_requires_okta_idp_message("--target okta-dashboard")
        assert "--target okta-dashboard" in message
        assert "--idp okta" in message

    def test_it_matches_the_wording_of_the_checks_that_already_exist(self):
        # Byte-identical to the message _validate_mode produces at cli.py:160, so
        # the new checks do not read like a different tool.
        assert errors.flag_requires_okta_idp_message("--okta-svc-aes") == (
            "--okta-svc-aes requires --idp okta"
        )


class TestFlagIgnoredMessage:
    def test_it_names_the_flag_and_the_reason(self):
        message = errors.flag_ignored_message("--user-sid", because="in --ccache mode")
        assert "--user-sid" in message
        assert "in --ccache mode" in message

    def test_the_reason_is_keyword_only(self):
        with pytest.raises(TypeError):
            errors.flag_ignored_message("--user-sid", "in --ccache mode")

    def test_it_carries_no_prefix(self):
        # cli.py owns the "Warning: " prefix and the choice of stream.
        message = errors.flag_ignored_message("--user-sid", because="in --ccache mode")
        assert not message.startswith("Warning: ")


class TestTicketFileMessage:
    def test_it_names_the_flag_the_path_and_the_reason(self):
        message = errors.ticket_file_message(
            "/tmp/x.ccache", reason=errors.TICKET_REASON_MISSING, flag="--ccache"
        )
        assert message == "--ccache /tmp/x.ccache: no such file"

    def test_without_a_flag_it_names_the_path_and_the_reason(self):
        message = errors.ticket_file_message(
            "/tmp/x.ccache", reason=errors.TICKET_REASON_DIRECTORY
        )
        assert message == "/tmp/x.ccache: it is a directory, not a ticket file"

    def test_the_reason_and_the_flag_are_keyword_only(self):
        with pytest.raises(TypeError):
            errors.ticket_file_message("/tmp/x.ccache", errors.TICKET_REASON_MISSING)

    @pytest.mark.parametrize(
        "reason",
        [
            "TICKET_REASON_MISSING",
            "TICKET_REASON_DIRECTORY",
            "TICKET_REASON_UNREADABLE",
            "TICKET_REASON_UNREADABLE_OTHER",
            "TICKET_REASON_NO_CREDENTIALS",
        ],
    )
    def test_every_reason_constant_renders_into_the_message(self, reason):
        # Fails by name if a later task invents a sixth reason as a literal at the
        # call site instead of a constant here.
        text = getattr(errors, reason)
        message = errors.ticket_file_message("/tmp/x.ccache", reason=text)
        assert text in message
        assert "/tmp/x.ccache" in message
        assert not message.startswith("Error: ")


class TestSpnMismatchMessage:
    AZURE_SPN = "HTTP/autologon.microsoftazuread-sso.com"

    def test_it_names_every_spn_found_and_the_one_expected(self):
        message = errors.spn_mismatch_message(
            ("HTTP/other.example.com@TEST.LOCAL", "HTTP/third.example.com@TEST.LOCAL"),
            expected=self.AZURE_SPN,
        )
        assert "HTTP/other.example.com@TEST.LOCAL" in message
        assert "HTTP/third.example.com@TEST.LOCAL" in message
        assert self.AZURE_SPN in message

    def test_it_says_the_run_continues(self):
        # It is a warning, not an error: an operator who sees it must know the run
        # did not stop, or they will go looking for a failure that did not happen.
        message = errors.spn_mismatch_message(
            ("HTTP/other.example.com@TEST.LOCAL",), expected=self.AZURE_SPN
        )
        assert "continuing anyway" in message

    def test_an_empty_tuple_still_renders(self):
        message = errors.spn_mismatch_message((), expected=self.AZURE_SPN)
        assert "none" in message

    def test_the_expected_spn_is_keyword_only(self):
        with pytest.raises(TypeError):
            errors.spn_mismatch_message(("HTTP/x",), self.AZURE_SPN)

    def test_it_carries_no_prefix(self):
        # cli.py owns the "Warning: " prefix and the choice of stream.
        message = errors.spn_mismatch_message((), expected=self.AZURE_SPN)
        assert not message.startswith("Warning: ")


class TestOktaOrgNotDerivableMessage:
    """C7.2: the exit-3 text for an Okta run whose ticket has no host to derive from."""

    AZURE_SPN = "HTTP/autologon.microsoftazuread-sso.com@TEST.LOCAL"
    PATH = "/tmp/imported.ccache"

    def test_it_names_the_path_and_every_spn_found(self):
        message = errors.okta_org_not_derivable_message(
            self.PATH, found_spns=(self.AZURE_SPN, "HTTP/fileserver.corp.local@TEST.LOCAL")
        )
        assert self.PATH in message
        assert self.AZURE_SPN in message
        assert "HTTP/fileserver.corp.local@TEST.LOCAL" in message

    def test_it_names_both_ways_out(self):
        message = errors.okta_org_not_derivable_message(self.PATH, found_spns=(self.AZURE_SPN,))
        assert "--okta-org" in message
        assert "--idp azure" in message

    def test_an_empty_tuple_reads_as_none(self):
        # Matches spn_mismatch_message's convention rather than rendering "found ".
        message = errors.okta_org_not_derivable_message(self.PATH, found_spns=())
        assert "found none" in message

    def test_it_stays_inside_the_okta_register(self):
        # Read from forbidden_terms, never restated: this message must be free to say
        # "Okta" and must not name Microsoft's product or the Azure SSO account.
        message = errors.okta_org_not_derivable_message(self.PATH, found_spns=(self.AZURE_SPN,))
        assert "Okta" in message
        assert not [t for t in errors.forbidden_terms(errors.IDP_OKTA) if t in message]

    def test_found_spns_is_keyword_only(self):
        with pytest.raises(TypeError):
            errors.okta_org_not_derivable_message(self.PATH, (self.AZURE_SPN,))


KDC_REASON_NAMES = [
    "KDC_REASON_REFUSED",
    "KDC_REASON_TIMEOUT",
    "KDC_REASON_DNS",
    "KDC_REASON_OTHER",
]


class TestKdcUnreachableMessage:
    """S2-R11: the exit-4 text for a KDC this host could not reach."""

    ADDRESS = "dc.example.local:88"

    def test_the_refused_message_is_the_text_the_spec_pins(self):
        # The one message in this part whose wording the stage spec pins, so it is
        # asserted whole rather than by substring.
        assert errors.kdc_unreachable_message("127.0.0.1:88", reason=errors.KDC_REASON_REFUSED) == (
            "could not reach the KDC at 127.0.0.1:88 (connection refused). Check --dc-ip "
            "and that the host is routable."
        )

    @pytest.mark.parametrize("reason", KDC_REASON_NAMES)
    def test_every_reason_is_rendered_with_the_address_and_the_flag(self, reason):
        # Fails by name if a later task reports a fifth errno as a literal at the
        # call site instead of a constant here.
        text = getattr(errors, reason)
        message = errors.kdc_unreachable_message(self.ADDRESS, reason=text)
        assert self.ADDRESS in message
        assert text in message
        assert "--dc-ip" in message

    def test_the_reason_is_keyword_only(self):
        with pytest.raises(TypeError):
            errors.kdc_unreachable_message(self.ADDRESS, errors.KDC_REASON_REFUSED)

    def test_it_carries_no_prefix_and_no_trailing_newline(self):
        # cli.py owns the "Error: " prefix and the choice of stream.
        message = errors.kdc_unreachable_message(self.ADDRESS, reason=errors.KDC_REASON_TIMEOUT)
        assert not message.startswith("Error: ")
        assert not message.startswith("Warning: ")
        assert message == message.strip()

    @pytest.mark.parametrize("reason", KDC_REASON_NAMES)
    def test_it_names_no_vendor_product(self, reason):
        # Read from forbidden_terms, never restated. The sweep covers the one
        # parametrised case; this covers all four reasons.
        message = errors.kdc_unreachable_message(self.ADDRESS, reason=getattr(errors, reason))
        assert not [term for term in errors.forbidden_terms(None) if term in message]

    def test_the_four_reasons_are_distinct_and_non_empty(self):
        # Two reasons that collide would silently make the DNS case unreportable:
        # the caller picks by errno, so a duplicated string loses a whole branch.
        reasons = [getattr(errors, name) for name in KDC_REASON_NAMES]
        assert len(set(reasons)) == 4
        assert "" not in reasons


FIREFOX_REASON_NAMES = [
    "FIREFOX_REASON_NOT_EXECUTABLE",
    "FIREFOX_REASON_MISSING",
    "FIREFOX_REASON_EXEC_FORMAT",
    "FIREFOX_REASON_PERMISSION",
    "FIREFOX_REASON_OTHER",
]


class TestFirefoxLaunchMessage:
    """S2-R15 and S2-R16: the exit-1 text for a Firefox that exists but will not launch."""

    PATH = "/opt/firefox"

    def test_the_not_executable_sentence_is_the_text_the_gate_produces(self):
        # The find_firefox gate's own wording, asserted whole: the gate raises this text
        # and an end-to-end test in test_cli.py reads it back off stderr.
        message = errors.firefox_launch_message(
            self.PATH, reason=errors.FIREFOX_REASON_NOT_EXECUTABLE
        )
        assert message == "Firefox at /opt/firefox could not be launched: it is not executable"

    @pytest.mark.parametrize("reason", FIREFOX_REASON_NAMES)
    def test_no_reason_can_reach_either_frozen_not_found_message(self, reason):
        # launcher.py's "Firefox not found at <path>" and "Firefox not found on PATH.
        # ..." are frozen stderr, pinned by four tests in test_launcher.py, two with
        # ==. This builder is a third condition and must never collide with them.
        message = errors.firefox_launch_message(self.PATH, reason=getattr(errors, reason))
        assert "not found" not in message

    @pytest.mark.parametrize("reason", FIREFOX_REASON_NAMES)
    def test_every_reason_is_rendered_with_the_path(self, reason):
        # Fails by name if a later task reports a sixth condition as a literal at the
        # call site instead of a constant here.
        text = getattr(errors, reason)
        message = errors.firefox_launch_message(self.PATH, reason=text)
        assert text in message
        assert self.PATH in message

    def test_the_reason_is_keyword_only(self):
        with pytest.raises(TypeError):
            errors.firefox_launch_message(self.PATH, errors.FIREFOX_REASON_OTHER)

    def test_it_carries_no_prefix_and_no_trailing_newline(self):
        # cli.py and launcher.py own the "Error: " prefix and the choice of stream.
        message = errors.firefox_launch_message(self.PATH, reason=errors.FIREFOX_REASON_MISSING)
        assert not message.startswith("Error: ")
        assert not message.startswith("Warning: ")
        assert message == message.strip()

    def test_the_five_reasons_are_distinct_and_non_empty(self):
        # The Popen call site picks four of these by errno; two that collide would
        # make a whole branch indistinguishable to the operator reading stderr.
        reasons = [getattr(errors, name) for name in FIREFOX_REASON_NAMES]
        messages = {errors.firefox_launch_message(self.PATH, reason=text) for text in reasons}
        assert len(messages) == 5
        assert "" not in reasons


PATH_REASON_NAMES = [
    "PATH_REASON_PERMISSION",
    "PATH_REASON_READ_ONLY",
    "PATH_REASON_NO_SPACE",
    "PATH_REASON_OTHER",
]


class TestUnwritablePathMessage:
    """S2-R17: the exit-1 text for a profile or krb5.conf that could not be written."""

    PATH = "/tmp/sso-x"

    def test_the_profile_sentence_is_exact(self):
        message = errors.unwritable_path_message(
            self.PATH,
            what=errors.PATH_WHAT_FIREFOX_PROFILE,
            reason=errors.PATH_REASON_PERMISSION,
        )
        assert message == "could not write the Firefox profile under /tmp/sso-x: permission denied"

    def test_the_krb5_conf_sentence_names_krb5_conf_and_the_same_directory(self):
        # The path is the temp directory both artefacts live under, not the file
        # inside it: <temp_dir>/profile and <temp_dir>/krb5.conf is profile.py's
        # layout and is not duplicated into a message. what carries which failed.
        message = errors.unwritable_path_message(
            self.PATH,
            what=errors.PATH_WHAT_KRB5_CONF,
            reason=errors.PATH_REASON_NO_SPACE,
        )
        assert message == "could not write krb5.conf under /tmp/sso-x: the filesystem is full"

    @pytest.mark.parametrize("reason", PATH_REASON_NAMES)
    def test_every_reason_is_rendered_with_the_artefact_and_the_directory(self, reason):
        # Fails by name if a later task reports a fifth errno as a literal at the
        # call site instead of a constant here.
        text = getattr(errors, reason)
        message = errors.unwritable_path_message(
            self.PATH, what=errors.PATH_WHAT_FIREFOX_PROFILE, reason=text
        )
        assert text in message
        assert errors.PATH_WHAT_FIREFOX_PROFILE in message
        assert self.PATH in message

    def test_what_and_the_reason_are_keyword_only(self):
        with pytest.raises(TypeError):
            errors.unwritable_path_message(
                self.PATH, errors.PATH_WHAT_KRB5_CONF, errors.PATH_REASON_OTHER
            )

    def test_it_carries_no_prefix_and_no_trailing_newline(self):
        # cli.py owns the "Error: " prefix and the choice of stream.
        message = errors.unwritable_path_message(
            self.PATH, what=errors.PATH_WHAT_KRB5_CONF, reason=errors.PATH_REASON_READ_ONLY
        )
        assert not message.startswith("Error: ")
        assert not message.startswith("Warning: ")
        assert message == message.strip()

    def test_the_four_reasons_are_distinct_and_non_empty(self):
        # The cli.py call site picks by errno; two that collide would make a whole
        # branch indistinguishable to the operator reading stderr.
        reasons = [getattr(errors, name) for name in PATH_REASON_NAMES]
        messages = {
            errors.unwritable_path_message(
                self.PATH, what=errors.PATH_WHAT_KRB5_CONF, reason=text
            )
            for text in reasons
        }
        assert len(messages) == 4
        assert "" not in reasons


# (builder name, the register the call sits in, kwargs other than idp) — one
# entry per register each builder can be called in. The sweep calls every entry
# and asserts the result names none of forbidden_terms(idp), so a message that
# says "Okta" on the Azure path fails the suite even though it goes to stderr,
# where TestOpsecMessages in test_cli.py cannot see it.
REGISTER_CASES = [
    # Every mapped KDC row whose wording is neutral, in both registers.
    *[
        ("kdc_error_message", idp, {"code": code, "code_name": code_name})
        for code_name, code, _ in NEUTRAL_KDC_ROWS
        for idp in (errors.IDP_AZURE, errors.IDP_OKTA)
    ],
    # The one row where the registers differ, with and without a known SPN.
    ("kdc_error_message", errors.IDP_AZURE, {"code": 7, "code_name": SPN_UNKNOWN}),
    (
        "kdc_error_message",
        errors.IDP_OKTA,
        {"code": 7, "code_name": SPN_UNKNOWN, "okta_spn": "HTTP/acme.kerberos.okta.com"},
    ),
    ("kdc_error_message", errors.IDP_OKTA, {"code": 7, "code_name": SPN_UNKNOWN}),
    # The default branch, from a code name and from the numeric code.
    (
        "kdc_error_message",
        errors.IDP_AZURE,
        {"code": 201, "code_name": "KDC_ERR_UNHEARD_OF", "detail": "the KDC said so"},
    ),
    ("kdc_error_message", errors.IDP_OKTA, {"code": 201, "detail": "the KDC said so"}),
    # The builders that take no idp, so the neutral register is what holds them.
    ("interrupted_message", None, {}),
    ("unexpected_failure_message", None, {"exc": ValueError("MARKER-2f9c-do-not-leak")}),
    (
        "ticket_kind_message",
        None,
        {"found_spn": "krbtgt/EXAMPLE.LOCAL", "expected": "a service ticket"},
    ),
    (
        "hex_format_message",
        None,
        {"flag": "--adssoacc-ntlm", "expected_lengths": (32, 64), "got_length": 31},
    ),
    ("sid_format_message", None, {"got": "NOT-A-SID"}),
    ("ntlm_hash_format_message", None, {"flag": "--user-password-hash", "got_length": 5}),
    ("flag_requires_okta_idp_message", None, {"flag": "--target okta-dashboard"}),
    (
        "flag_ignored_message",
        None,
        {"flag": "--user-sid", "because": "in --ccache, --tgs, --tgt and credential modes"},
    ),
    (
        "ticket_file_message",
        None,
        {
            "path": "/tmp/x.ccache",
            "reason": errors.TICKET_REASON_MISSING,
            "flag": "--ccache",
        },
    ),
    (
        "kdc_unreachable_message",
        None,
        {"address": "127.0.0.1:88", "reason": errors.KDC_REASON_REFUSED},
    ),
    (
        "firefox_launch_message",
        None,
        {"path": "/opt/firefox", "reason": errors.FIREFOX_REASON_NOT_EXECUTABLE},
    ),
    (
        "unwritable_path_message",
        None,
        {
            "path": "/tmp/sso-x",
            "what": errors.PATH_WHAT_FIREFOX_PROFILE,
            "reason": errors.PATH_REASON_PERMISSION,
        },
    ),
    (
        "spn_mismatch_message",
        None,
        {
            "found_spns": ("HTTP/other.example.com@TEST.LOCAL",),
            "expected": "HTTP/autologon.microsoftazuread-sso.com",
        },
    ),
    # Okta register, not neutral: this one has to say "Okta", which the neutral
    # list forbids, and it is only ever reached on the Okta path.
    (
        "okta_org_not_derivable_message",
        errors.IDP_OKTA,
        {
            "path": "/tmp/imported.ccache",
            "found_spns": ("HTTP/autologon.microsoftazuread-sso.com@TEST.LOCAL",),
        },
    ),
]

# Public callables in __all__ that are not message builders. forbidden_terms
# takes an idp and returns the forbidden terms themselves, so it is the contract
# the sweep reads rather than text the sweep checks.
NOT_A_MESSAGE_BUILDER = {"forbidden_terms"}


def _call_builder(name: str, idp: str | None, kwargs: dict) -> str:
    builder = getattr(errors, name)
    if "idp" in inspect.signature(builder).parameters:
        return builder(idp=idp, **kwargs)
    return builder(**kwargs)


def _public_builders() -> dict[str, object]:
    return {
        name: getattr(errors, name)
        for name in errors.__all__
        if name not in NOT_A_MESSAGE_BUILDER and inspect.isfunction(getattr(errors, name))
    }


def _swept_builders() -> set[str]:
    return {name for name, _, _ in REGISTER_CASES}


class TestRegisterSweep:
    @pytest.mark.parametrize("name,idp,kwargs", REGISTER_CASES)
    def test_no_message_names_a_term_its_register_forbids(self, name, idp, kwargs):
        message = _call_builder(name, idp, kwargs)
        leaked = [term for term in errors.forbidden_terms(idp) if term in message]
        assert not leaked, (
            f"{name} in the {idp or 'neutral'} register names {leaked}, which that "
            f"register forbids: {message!r}"
        )

    @pytest.mark.parametrize("name,idp,kwargs", REGISTER_CASES)
    def test_no_message_carries_the_prefix_or_a_trailing_newline(self, name, idp, kwargs):
        # cli.py owns the "Error: " prefix and the choice of stream.
        message = _call_builder(name, idp, kwargs)
        assert message
        assert not message.startswith("Error: ")
        assert message == message.rstrip("\n")

    def test_no_builder_escapes_the_sweep(self):
        idp_aware = {
            name
            for name, builder in _public_builders().items()
            if "idp" in inspect.signature(builder).parameters
        }
        missing = sorted(idp_aware - _swept_builders())
        assert not missing, (
            f"{missing} take an idp and have no case in REGISTER_CASES, so nothing "
            "holds them to the register contract; add one case per register."
        )

    def test_every_public_builder_has_a_register_case(self):
        missing = sorted(set(_public_builders()) - _swept_builders())
        assert not missing, (
            f"{missing} are public message builders with no case in REGISTER_CASES; "
            "add one case per register each can be called in."
        )

    def test_an_idp_aware_builder_is_swept_in_both_registers(self):
        both = {errors.IDP_AZURE, errors.IDP_OKTA}
        uncovered = {}
        for name, builder in _public_builders().items():
            if "idp" not in inspect.signature(builder).parameters:
                continue
            swept = {idp for case_name, idp, _ in REGISTER_CASES if case_name == name}
            if both - swept:
                uncovered[name] = sorted(both - swept)
        assert not uncovered, (
            f"{uncovered} are swept in one register only, so the other register's "
            "forbidden terms are never checked against them."
        )


def _errors_ast() -> ast.Module:
    source = pathlib.Path(errors.__file__).read_text()
    return ast.parse(source)


class TestLeafModule:
    def test_imports_nothing_from_the_project_or_impacket(self):
        forbidden = ("seamless_sso_browser", "impacket")
        found = []
        for node in ast.walk(_errors_ast()):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""] + [alias.name for alias in node.names]
            else:
                continue
            for name in names:
                if any(name == f or name.startswith(f + ".") for f in forbidden):
                    found.append(f"line {node.lineno}: {name}")
        assert not found, (
            "errors.py is a leaf module and must import neither the project nor "
            f"impacket, but it imports {found}"
        )

    def test_calls_neither_print_nor_exit(self):
        found = []
        for node in ast.walk(_errors_ast()):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in ("print", "exit"):
                found.append(f"line {node.lineno}: {func.id}()")
            elif isinstance(func, ast.Attribute) and func.attr == "exit":
                found.append(f"line {node.lineno}: .{func.attr}()")
        assert not found, (
            "errors.py holds message text and types only and must never write output "
            f"or exit the process, but it calls {found}"
        )
