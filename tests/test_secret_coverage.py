"""Synthetic regressions for credential coverage; never use captured credentials here."""

import base64
import json

import pytest

from dataclaw.secrets import REDACTED, redact_session, redact_text, scan_text, transform_session


def _b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


DISCORD = _b64(b"123456789012345678") + ".ABC123." + "SyntheticSignature0123456789_XY"
FAL_SECRET = "SyntheticSecret0123456789ABCDEFgh"
FAL = "00000000-0000-4000-8000-000000000001:" + FAL_SECRET
ZHIPU = "0123456789abcdef" * 2 + ".NotARealKey12345"
OPAQUE = "SyntheticOpaqueValue0123456789"
JWT = ".".join(
    [
        _b64(b'{"alg":"HS256","typ":"JWT"}'),
        _b64(b'{"iss":"supabase","role":"service_role","ref":"synthetic_project"}'),
        "SyntheticSignatureNotReal0123456789",
    ]
)


@pytest.mark.parametrize(
    "credential",
    [
        DISCORD,
        "mfa." + "Synthetic0123456789" * 5,
        FAL,
        ZHIPU,
        "sk-" + "0123456789abcdef" * 2,  # DeepSeek-compatible 32-hex form
        "sk-or-v1-" + "0123456789abcdef" * 4,
        "sk-cp-" + "Ab0" * 30 + "-" + "xY2" * 9,
        "sk-api-" + "Synthetic0123456789" * 4,
        "sk-proj-" + "Synthetic_0123456789-" * 8,
        "sk-svcacct-" + "Synthetic_0123456789-" * 5,
        "sb_secret_" + "Synthetic0123456789" * 2,
        "AIzaSy" + "A" * 33,
        JWT,
    ],
)
def test_entire_bare_provider_credential_is_removed(credential):
    # Equality, not only absence of the full key, catches surviving suffixes.
    assert redact_text(credential) == (REDACTED, 1)


@pytest.mark.parametrize("scheme", ["Bot", "bot", "BOT", "Bearer", "bearer"])
def test_authorization_schemes_are_case_insensitive(scheme):
    text, count = redact_text(f"Authorization: {scheme} {OPAQUE}")
    assert OPAQUE not in text
    assert count == 1


@pytest.mark.parametrize(
    "name",
    [
        "DISCORD_BOT_TOKEN_TANTE_ROSI",
        "OPENROUTER_API_KEY_1",
        "MINIMAX_API_KEY_2",
        "ZHIPU_API_KEY_3",
        "FAL_KEY_BACKUP",
        "apiKey",
        "refreshToken",
        "api-key-production",
        "access_token_42",
    ],
)
@pytest.mark.parametrize("delimiter", ["=", ": ", "\t=\t", "\n=\n", " "])
def test_secret_name_components_and_fast_paths(name, delimiter):
    text, count = redact_text(f"{name}{delimiter}{OPAQUE}")
    assert OPAQUE not in text
    assert count == 1


@pytest.mark.parametrize("value", [FAL, "Synthetic0123456789:second:third", "Synthetic0123456789!@%:tail"])
def test_opaque_context_redacts_complete_colon_and_punctuation_values(value):
    assert redact_text(f"API_KEY_BACKUP={value}") == (REDACTED, 1)


def test_quoted_secret_and_query_parameter_boundaries():
    assert redact_text('SECRET_1="Synthetic password with spaces, commas & punctuation!"')[0] == REDACTED
    text, _ = redact_text(f"https://example.com?api_key_1={OPAQUE}&limit=5")
    assert OPAQUE not in text
    assert text.endswith("&limit=5")


@pytest.mark.parametrize(
    "text",
    [
        "00000000-0000-4000-8000-000000000001",
        "0123456789abcdef" * 2,
        "sk-process-conversation-history",
        f"monkey={OPAQUE}",
        "passwordless authentication is supported",
        "passwordLookupFunction",
        "API_KEY_1='your_api_key_here'",
        "API_KEY_1=${SYNTHETIC_API_KEY}",
        'API_KEY_1="process.env.SYNTHETIC_API_KEY"',
        _b64(b"not-a-numeric-account") + ".ABC123." + "SyntheticSignature0123456789_XY",
    ],
)
def test_identifiers_lookup_expressions_and_explicit_placeholders_are_not_credentials(text):
    assert redact_text(text) == (text, 0)


@pytest.mark.parametrize(
    "text",
    [
        "TOKEN_1=Synthetic0123456789:192.168.1.10:tail",
        'API_KEY_1="Synthetic:noreply@example.com:secret"',
        "postgres://realuser:SyntheticPassword123@localhost:5432/mydb",
        "postgres://realuser:SyntheticPassword123@192.168.1.10:5432/mydb",
    ],
)
def test_pii_allowlists_cannot_exempt_credentials(text):
    assert redact_text(text) == (REDACTED, 1)


def test_overlapping_partial_jwt_and_full_jwt_redact_the_union():
    findings = scan_text(JWT)
    assert any(item["type"] == "jwt" for item in findings)
    assert any(item["type"] == "jwt_partial" and item["start"] > 0 for item in findings)
    assert redact_text(JWT) == (REDACTED, 1)
    assert redact_text(f"SUPABASE_SERVICE_ROLE_KEY={JWT}") == (REDACTED, 1)
    assert FAL_SECRET not in redact_text(f"FAL_KEY={FAL}")[0]


@pytest.mark.parametrize("prefix", ["A" * 9000 + "\n", "text\x00" * 1500 + "\n"])
def test_binary_looking_prefix_or_control_character_cannot_hide_later_secret(prefix):
    result, count = redact_text(prefix + DISCORD)
    assert DISCORD not in result
    assert count == 1


@pytest.mark.parametrize("with_anonymizer", [False, True])
def test_all_session_fields_and_structured_secret_names_are_walked(with_anonymizer, mock_anonymizer):
    session = {
        "session_id": "ordinary-session-id",
        "metadata": {"API_KEY_1": OPAQUE, "other": [DISCORD]},
        "model": "sk-proj-" + "Synthetic0123456789" * 3,
        "messages": [
            {"extra": {"headers": {"Authorization": "Bot " + OPAQUE}}, "tool_uses": [{"provider_extension": [FAL]}]}
        ],
    }
    if with_anonymizer:
        result, count = transform_session(session, mock_anonymizer)
    else:
        result, count = redact_session(session)
    assert result is session
    assert result["session_id"] == "ordinary-session-id"
    assert result["metadata"]["API_KEY_1"] == REDACTED
    assert result["model"] == REDACTED
    rendered = json.dumps(result)
    assert all(secret not in rendered for secret in [OPAQUE, DISCORD, FAL_SECRET])
    assert count == 5


def test_secret_bearing_dictionary_keys_do_not_collide_or_lose_values():
    session = {"extension": {DISCORD: "one", FAL: "two", REDACTED: "three"}}
    result, count = redact_session(session)
    assert len(result["extension"]) == 3
    assert set(result["extension"].values()) == {"one", "two", "three"}
    assert all(secret not in json.dumps(result) for secret in [DISCORD, FAL_SECRET])
    assert count == 2


def test_embedded_json_preserves_context_and_schema_exemptions(mock_anonymizer):
    embedded = {"model": "testuser-model", "extra": {"API_KEY_2": OPAQUE}}
    wrapped = json.dumps({"nested": json.dumps(embedded)})
    session = {"messages": [wrapped], "new_field": "owned by testuser"}
    result, count = transform_session(session, mock_anonymizer)
    decoded = json.loads(json.loads(result["messages"][0])["nested"])
    assert decoded["model"] == "testuser-model"
    assert decoded["extra"]["API_KEY_2"] == REDACTED
    assert "testuser" not in result["new_field"]
    assert count == 1


def test_unchanged_embedded_json_keeps_original_format():
    original = '{ "metadata": [1, null, "ordinary"] }'
    result, count = redact_session({"new_field": original})
    assert result["new_field"] == original
    assert count == 0


def test_custom_redaction_reaches_metadata_and_dictionary_keys():
    result, count = redact_session({"new_field": {"SyntheticCompany": "SyntheticCompany"}}, ["SyntheticCompany"])
    assert result == {"new_field": {REDACTED: REDACTED}}
    assert count == 2


@pytest.mark.parametrize("value", ["Fake!123", "Fake:123", "Fake12!@", "Fake 123!"])
def test_short_contextual_password_is_removed_completely(value):
    assert redact_text(f'PASSWORD_BACKUP="{value}"') == (REDACTED, 1)
    result, count = redact_session({"metadata": {"PASSWORD_BACKUP": value}})
    assert result["metadata"]["PASSWORD_BACKUP"] == REDACTED
    assert count == 1


@pytest.mark.parametrize("credential", [DISCORD, ZHIPU])
def test_sentence_punctuation_does_not_hide_provider_token(credential):
    assert redact_text(f"Use {credential}.") == (f"Use {REDACTED}.", 1)


@pytest.mark.parametrize("value", ["process.env.Synthetic0123456789:actualSecret", "os.getenv.Synthetic0123456789"])
def test_lookup_prefix_is_not_a_blanket_credential_exemption(value):
    assert redact_text(f'API_KEY="{value}"') == (REDACTED, 1)
    assert redact_session({"API_KEY": value}) == ({"API_KEY": REDACTED}, 1)


@pytest.mark.parametrize(
    "value", ["process.env.SYNTHETIC_KEY", "os.getenv('SYNTHETIC_KEY')", 'os.environ["SYNTHETIC_KEY"]']
)
def test_complete_lookup_expressions_are_preserved(value):
    assert redact_session({"API_KEY": value}) == ({"API_KEY": value}, 0)


def test_secret_named_opaque_value_is_not_skipped_as_binary():
    assert redact_session({"API_KEY_BACKUP": "Ab12" * 1100}) == ({"API_KEY_BACKUP": REDACTED}, 1)
    assert redact_session({"PASSWD": "Fake 123!"}) == ({"PASSWD": REDACTED}, 1)
