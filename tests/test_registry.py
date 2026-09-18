from __future__ import annotations

import pytest

from sluice.tools import FS_READ, ToolRegistry, make_spec, tool


@tool(caps=[FS_READ], fields={"body": "tool.fs.body"})
def read_file(
    path: str, limit: int = 10, tags: list[str] | None = None, meta: dict[str, str] | None = None
) -> str:
    """Read a file."""
    return path


def plain(x: float, flag: bool) -> float:
    return x


def test_decorator_spec() -> None:
    reg = ToolRegistry([read_file, plain])
    spec = reg.get("read_file")
    assert spec is not None
    assert spec.source == "tool.read_file"
    assert spec.caps == {FS_READ}
    assert spec.description == "Read a file."
    schema = spec.json_schema()
    props = schema["input_schema"]["properties"]
    assert props["path"] == {"type": "string"}
    assert props["limit"] == {"type": "integer"}
    assert schema["input_schema"]["required"] == ["path"]
    p = reg.get("plain")
    assert (
        p is not None
        and p.params["x"] == {"type": "number"}
        and p.params["flag"] == {"type": "boolean"}
    )
    assert "read_file" in reg and len(reg) == 2 and len(reg.schemas()) == 2
    assert [s.name for s in reg] == ["read_file", "plain"]


def test_container_params() -> None:
    def f(xs: list[int], d: dict[str, int]) -> None: ...

    s = make_spec(f)
    assert s.params["xs"] == {"type": "array"} and s.params["d"] == {"type": "object"}


def test_duplicate_and_unknown_caps() -> None:
    reg = ToolRegistry([plain])
    with pytest.raises(ValueError, match="already registered"):
        reg.register(plain)
    with pytest.raises(ValueError, match="unknown capability"):
        make_spec(plain, caps=["teleport"])


def test_register_spec_directly() -> None:
    reg = ToolRegistry()
    spec = make_spec(plain, name="p2", source="custom")
    assert reg.register(spec) is spec and reg.get("p2") is spec and reg.get("nope") is None


def test_spec_manifest_roundtrip() -> None:
    from sluice.labels import Confidentiality
    from sluice.labels.requirement import Requirement
    from sluice.tools.registry import spec_from_dict, spec_to_dict

    spec = make_spec(
        plain,
        sink={"x": Requirement.trusted()},
        all_args=Requirement(max_confidentiality=Confidentiality.INTERNAL),
        fields={"a": "b"},
    )
    back = spec_from_dict(spec_to_dict(spec))
    assert spec_to_dict(back) == spec_to_dict(spec)
    with pytest.raises(RuntimeError, match="cannot be executed"):
        back.fn(1)
    bare = spec_from_dict({"name": "n", "source": "s", "sink": {"q": {}}})
    assert bare.all_args is None and bare.sink == {"q": Requirement()}
