from helianthus_vrc_explorer.ebusd import parse_ebusd_info_target_addresses
from helianthus_vrc_explorer.protocol.basv import (
    parse_scan_identification,
    parse_vaillant_scan_id_chunks,
)

_ROLE_INITIATOR_TOKEN = bytes.fromhex("6d6173746572").decode("ascii")
_ROLE_TARGET_TOKEN = bytes.fromhex("736c617665").decode("ascii")


def test_parse_scan_identification_parses_manufacturer_id_sw_hw() -> None:
    payload = bytes.fromhex("b556525f393104154803")  # Vaillant VR_91 SW=0415 HW=4803
    ident = parse_scan_identification(payload)
    assert ident.manufacturer == 0xB5
    assert ident.device_id == "VR_91"
    assert ident.sw == "0415"
    assert ident.hw == "4803"


def test_parse_vaillant_scan_id_chunks_parses_model_and_serial() -> None:
    raw = "21231600202609140000000001A1" + " " * 4
    segments = [raw[i : i + 8] for i in range(0, 32, 8)]
    chunks = [bytes([0x00]) + s.encode("ascii") for s in segments]

    scan_id = parse_vaillant_scan_id_chunks(chunks)
    assert scan_id.model_number == "0020260914"
    assert scan_id.serial_number == "21231600202609140000000001A1"
    assert scan_id.serial_number_short == "2123160000000001A1"


def test_parse_vaillant_scan_id_chunks_supports_raw_9byte_variant() -> None:
    raw = b"21213400202621480000000001N7"
    padded = raw + (b"\xff" * (36 - len(raw)))
    chunks = [padded[i : i + 9] for i in range(0, 36, 9)]

    scan_id = parse_vaillant_scan_id_chunks(chunks)
    assert scan_id.model_number == "0020262148"
    assert scan_id.serial_number == "21213400202621480000000001N7"
    assert scan_id.serial_number_short == "2121340000000001N7"


def test_parse_ebusd_info_target_addresses_filters_initiator_and_self() -> None:
    lines = [
        f"address 03: {_ROLE_INITIATOR_TOKEN}",
        f"address 08: {_ROLE_TARGET_TOKEN}, scanned Vaillant;BAI00;0703;7401",
        f"address 31: {_ROLE_INITIATOR_TOKEN}, self",
        f"address 36: {_ROLE_TARGET_TOKEN}, self",
    ]
    assert parse_ebusd_info_target_addresses(lines) == [0x08]
