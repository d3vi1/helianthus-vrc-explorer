from helianthus_vrc_explorer.ebusd import parse_ebusd_info_slave_addresses
from helianthus_vrc_explorer.protocol.basv import (
    parse_scan_identification,
    parse_vaillant_scan_id_chunks,
)


def test_parse_scan_identification_parses_manufacturer_id_sw_hw() -> None:
    payload = bytes.fromhex("b556525f393104154803")  # Vaillant VR_91 SW=0415 HW=4803
    ident = parse_scan_identification(payload)
    assert ident.manufacturer == 0xB5
    assert ident.device_id == "VR_91"
    assert ident.sw == "0415"
    assert ident.hw == "4803"


def test_parse_vaillant_scan_id_chunks_parses_model_and_serial() -> None:
    raw = "21231600202609140953035469N6" + " " * 4
    segments = [raw[i : i + 8] for i in range(0, 32, 8)]
    chunks = [bytes([0x00]) + s.encode("ascii") for s in segments]

    scan_id = parse_vaillant_scan_id_chunks(chunks)
    assert scan_id.model_number == "0020260914"
    assert scan_id.serial_number == "2123160953035469N6"


def test_parse_ebusd_info_slave_addresses_filters_masters_and_self() -> None:
    lines = [
        "address 03: master",
        "address 08: slave, scanned Vaillant;BAI00;0703;7401",
        "address 31: master, self",
        "address 36: slave, self",
    ]
    assert parse_ebusd_info_slave_addresses(lines) == [0x08]
