"""User/password pair extraction from extracted_fields lists."""

from __future__ import annotations

from sharesift.verify._pairs import extract_user_password_pairs


def test_extracts_unattend_pair():
    fields = [
        {"field_name": "Username", "value": "Administrator", "confidence": 0.95, "parser": "unattend", "context": ""},
        {"field_name": "Password", "value": "P@ssw0rd!", "confidence": 0.95, "parser": "unattend", "context": ""},
    ]
    pairs = extract_user_password_pairs(fields)
    assert len(pairs) == 1
    assert pairs[0].username == "Administrator"
    assert pairs[0].password == "P@ssw0rd!"
    assert pairs[0].parser == "unattend"


def test_multiple_users_paired_by_position():
    """tomcat-users yields N users + N passwords in document order."""
    fields = [
        {"field_name": "username", "value": "admin", "confidence": 0.95, "parser": "tomcat_users"},
        {"field_name": "username", "value": "tomcat", "confidence": 0.95, "parser": "tomcat_users"},
        {"field_name": "password", "value": "adminpass", "confidence": 0.95, "parser": "tomcat_users"},
        {"field_name": "password", "value": "tomcatpass", "confidence": 0.95, "parser": "tomcat_users"},
    ]
    pairs = extract_user_password_pairs(fields)
    assert len(pairs) == 2
    pair_set = {(p.username, p.password) for p in pairs}
    assert ("admin", "adminpass") in pair_set
    assert ("tomcat", "tomcatpass") in pair_set


def test_missing_username_yields_no_pair():
    fields = [
        {"field_name": "Password", "value": "secret", "confidence": 0.95, "parser": "x"},
    ]
    assert extract_user_password_pairs(fields) == []


def test_missing_password_yields_no_pair():
    fields = [
        {"field_name": "Username", "value": "admin", "confidence": 0.95, "parser": "x"},
    ]
    assert extract_user_password_pairs(fields) == []


def test_cross_parser_fields_not_paired():
    """Username from one parser + password from another shouldn't pair."""
    fields = [
        {"field_name": "Username", "value": "admin", "confidence": 0.95, "parser": "unattend"},
        {"field_name": "Password", "value": "secret", "confidence": 0.95, "parser": "my_cnf"},
    ]
    assert extract_user_password_pairs(fields) == []


def test_dotted_field_names():
    """spring.datasource.username + spring.datasource.password should pair."""
    fields = [
        {"field_name": "spring.datasource.username", "value": "dbuser", "confidence": 0.9, "parser": "application_properties"},
        {"field_name": "spring.datasource.password", "value": "dbpass", "confidence": 0.9, "parser": "application_properties"},
    ]
    pairs = extract_user_password_pairs(fields)
    assert len(pairs) == 1
    assert pairs[0].username == "dbuser"
    assert pairs[0].password == "dbpass"


def test_empty_input_returns_empty_list():
    assert extract_user_password_pairs([]) == []
    assert extract_user_password_pairs(None) == []  # type: ignore[arg-type]
