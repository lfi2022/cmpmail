from app.services.mail import result


def test_move_result_contract_documents_uid_remap():
    mapping = {
        "old_uid": 42,
        "old_mailbox": "INBOX",
        "new_uid": 9,
        "new_mailbox": "Archive",
        "message_id": "<move@example.test>",
    }
    response = result([mapping])
    assert response["data"][0]["old_uid"] != response["data"][0]["new_uid"]
    assert response["data"][0]["message_id"] == "<move@example.test>"
