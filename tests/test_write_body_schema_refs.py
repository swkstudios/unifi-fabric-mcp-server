"""Required object bodies remain guarded when tool schemas use local references."""

from types import SimpleNamespace

import pytest

from unifi_fabric.write_body import body_argument


def _tool(schema, definitions):
    return SimpleNamespace(
        annotations=SimpleNamespace(read_only_hint=False),
        parameters={
            "properties": {"settings": schema},
            "required": ["settings"],
            "$defs": definitions,
        },
    )


@pytest.mark.parametrize(
    "schema,definitions",
    [
        ({"$ref": "#/$defs/Settings"}, {"Settings": {"type": "object"}}),
        (
            {"anyOf": [{"$ref": "#/$defs/Settings"}, {"type": "null"}]},
            {"Settings": {"type": "object"}},
        ),
        (
            {"$ref": "#/$defs/Alias"},
            {"Alias": {"$ref": "#/$defs/Settings"}, "Settings": {"type": "object"}},
        ),
        ({"$ref": "#/$defs/A~1B~0C"}, {"A/B~C": {"type": "object"}}),
        (
            {"anyOf": [{"$ref": "#/$defs/Loop"}, {"type": "object"}]},
            {"Loop": {"$ref": "#/$defs/Loop"}},
        ),
    ],
)
def test_local_object_refs_are_required_write_bodies(schema, definitions):
    assert body_argument(_tool(schema, definitions)) == "settings"


@pytest.mark.parametrize(
    "schema,definitions",
    [
        ({"$ref": "#/$defs/Settings"}, {"Settings": {"type": "string"}}),
        ({"$ref": "#/$defs/Missing"}, {}),
        ({"$ref": "https://synthetic.invalid/settings"}, {}),
        ({"$ref": "#/$defs/Loop"}, {"Loop": {"$ref": "#/$defs/Loop"}}),
        (
            {"$ref": "#/$defs/A"},
            {"A": {"$ref": "#/$defs/B"}, "B": {"$ref": "#/$defs/A"}},
        ),
    ],
)
def test_non_objects_unresolved_and_cyclic_refs_are_not_write_bodies(schema, definitions):
    assert body_argument(_tool(schema, definitions)) is None


def test_optional_referenced_objects_are_not_required_write_bodies():
    tool = _tool({"$ref": "#/$defs/Settings"}, {"Settings": {"type": "object"}})
    tool.parameters["required"] = []
    assert body_argument(tool) is None


def test_two_required_referenced_objects_are_not_one_body():
    tool = _tool({"$ref": "#/$defs/Settings"}, {"Settings": {"type": "object"}})
    tool.parameters["properties"]["other"] = {"$ref": "#/$defs/Settings"}
    tool.parameters["required"].append("other")
    assert body_argument(tool) is None
