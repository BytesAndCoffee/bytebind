"""Regressions for hostile input at the relying-party boundary."""
import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from flask import Flask
from pydantic import BaseModel
from starlette.requests import Request

from bytebind.binding import check_requirements
from bytebind.fastapi import ByteBind as FastBind
from bytebind.flask import ByteBind as FlaskBind
from bytebind.limits import declared_fits, read_capped
from bytebind.rp import Lease
from conftest import APP


@pytest.mark.parametrize("binding", [FastBind, FlaskBind])
def test_generator_requirements_cannot_bypass_authorization(binding):
    class RP:
        def session(self, token):
            return Lease("node", {"tags": []}, 9999999999)

    app = FastAPI() if binding is FastBind else Flask(__name__)
    bind = binding(app, rp=RP())
    calls = []

    @app.get("/private")
    @bind(require=(item for item in ["tag:admin"]))
    def private():
        calls.append(True)
        return {}

    if binding is FastBind:
        with TestClient(app, base_url=APP) as client:
            assert client.get("/private").status_code == 403
    else:
        assert app.test_client().get("/private", base_url=APP).status_code == 403
    assert not calls


@pytest.mark.parametrize("invalid", [None, 1, "tag:admin", [""], [None]])
def test_invalid_requirements_fail_at_registration(invalid):
    with pytest.raises(ValueError):
        check_requirements(invalid)


@pytest.mark.parametrize("binding", [FastBind, FlaskBind])
def test_proof_input_is_bounded_before_rp(binding):
    class RP:
        def accept_proof(self, *args):
            pytest.fail("oversized or malformed proof reached the RP")

    app = FastAPI() if binding is FastBind else Flask(__name__)
    binding(app, rp=RP(), max_transaction_body=1)
    if binding is FastBind:
        with TestClient(app, base_url=APP) as client:
            assert client.post("/bytebind/proof", content=b"x" * 1025).status_code == 413
            assert client.post("/bytebind/proof", content=b"{").status_code == 401
            assert client.post("/bytebind/proof", content=iter([b"x" * 600, b"x" * 600])).status_code == 413
    else:
        client = app.test_client()
        assert client.post("/bytebind/proof", data=b"x" * 1025, base_url=APP).status_code == 413
        assert client.post("/bytebind/proof", data=b"{", base_url=APP).status_code == 401


def test_fastapi_bounds_model_body_before_validation():
    app = FastAPI()
    bind = FastBind(app, rp=object(), max_transaction_body=64)

    class Payload(BaseModel):
        text: str

    @app.post("/operation")
    @bind(grant=bind.TRANSACTION)
    def operation(body: Payload):
        pytest.fail("handler ran without authorization")

    with TestClient(app, base_url=APP) as client:
        # Malformed oversized JSON must be refused before FastAPI attempts parsing.
        for body in [b"{" * 65, iter([b"{" * 40, b"{" * 40])]:
            response = client.post("/operation", content=body, headers={"Content-Type": "application/json"})
            assert response.status_code == 413
            assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("declared, expected", [(None, True), ("00064", True), ("65", False),
    ("9" * 5000, False), ("²", False), ("-1", False), ("", False)])
def test_content_length_is_ascii_and_bounded(declared, expected):
    assert declared_fits(declared, 64) is expected


def test_capped_read_stops_before_consuming_remaining_chunks():
    calls = []

    async def receive():
        calls.append(True)
        if len(calls) > 2:
            pytest.fail("continued consuming an oversized stream")
        return {"type": "http.request", "body": b"x" * 40, "more_body": True}

    request = Request({"type": "http", "headers": []}, receive)
    assert asyncio.run(read_capped(request, 64)) is None
    assert len(calls) == 2
