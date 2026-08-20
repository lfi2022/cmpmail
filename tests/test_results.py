from app.services.mail import failure, partial, result


def test_standard_results():
    assert result({"x": 1}) == {
        "success": True,
        "data": {"x": 1},
        "warnings": [],
        "errors": [],
    }
    assert failure("bad")["errors"] == ["bad"]
    value = partial([], 4, 1, ["one failed"])
    assert value["partial"] and value["processed"] == 4 and value["failed"] == 1
