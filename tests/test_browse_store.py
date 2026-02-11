from __future__ import annotations

from helianthus_vrc_explorer.ui.browse_store import BrowseStore


def _sample_artifact() -> dict[str, object]:
    return {
        "meta": {
            "destination_address": "0x15",
            "scan_timestamp": "2026-02-11T12:00:00Z",
        },
        "groups": {
            "0x00": {
                "name": "Regulator Parameters",
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0001": {
                                "value": 1.0,
                                "raw_hex": "00",
                                "tt_kind": "parameter_config",
                                "read_opcode": "0x02",
                                "ebusd_name": "regulator_param_1",
                            },
                            "0x0002": {
                                "value": 2.0,
                                "raw_hex": "0102",
                                "tt_kind": "parameter_limit",
                                "read_opcode": "0x06",
                                "myvaillant_name": "limit_value",
                            },
                            "0x0003": {
                                "value": 3.0,
                                "raw_hex": "03",
                                "tt_kind": "live_operational",
                                "read_opcode": "0x02",
                            },
                        }
                    }
                },
            }
        },
    }


def test_browse_store_builds_rows_and_prefers_myvaillant_name() -> None:
    store = BrowseStore.from_artifact(_sample_artifact())
    assert store.device_label == "Device 0x15"
    assert len(store.rows) == 3

    by_register = {row.register_key: row for row in store.rows}
    assert by_register["0x0001"].tab == "config"
    assert by_register["0x0002"].tab == "config_limits"
    assert by_register["0x0003"].tab == "state"
    assert by_register["0x0001"].name == "regulator_param_1"
    assert by_register["0x0002"].name == "limit_value"
    assert by_register["0x0003"].name == "0x0003"


def test_browse_store_filters_rows_for_tree_selection() -> None:
    store = BrowseStore.from_artifact(_sample_artifact())
    category_node = next(
        node
        for node in store.tree_nodes
        if node.level == "category" and node.category_key == "regulator"
    )
    group_node = next(
        node for node in store.tree_nodes if node.level == "group" and node.group_key == "0x00"
    )
    instance_node = next(
        node
        for node in store.tree_nodes
        if node.level == "instance" and node.group_key == "0x00" and node.instance_key == "0x00"
    )

    assert len(store.rows_for_selection(None, tab="state")) == 1
    assert len(store.rows_for_selection(category_node, tab="config")) == 1
    assert len(store.rows_for_selection(group_node, tab="config_limits")) == 1
    assert len(store.rows_for_selection(instance_node, tab="state")) == 1
