from __future__ import annotations

from dataclasses import dataclass


class BasvError(Exception):
    """Base class for BASV/broadcast protocol errors."""


class ScanIdParseError(BasvError, ValueError):
    """Raised when parsing a 0x0704 scan identification payload fails."""


class VaillantScanIdParseError(BasvError, ValueError):
    """Raised when parsing Vaillant scan-id chunks (B509 QQ=0x24..0x27) fails."""


@dataclass(frozen=True, slots=True)
class ScanIdentification:
    manufacturer: int
    device_id: str
    sw: str
    hw: str


@dataclass(frozen=True, slots=True)
class VaillantScanId:
    prefix: str
    year: str
    week: str
    product: str
    supplier: str
    counter: str
    suffix: str
    raw: str

    @property
    def model_number(self) -> str:
        return self.product

    @property
    def serial_number(self) -> str:
        # Keep the complete scan-id token as the serial identifier.
        return self.raw

    @property
    def serial_number_short(self) -> str:
        # Legacy shorthand used in earlier artifacts/logs.
        return f"{self.prefix}{self.year}{self.week}{self.supplier}{self.counter}{self.suffix}"


def parse_scan_identification(payload: bytes) -> ScanIdentification:
    """Parse a 0x0704 identification response payload (no length prefix).

    Expected layout (based on ebusd broadcast.csv for 0704):
    - manufacturer: 1 byte
    - device id: N bytes (ASCII)
    - software version: 2 bytes
    - hardware version: 2 bytes
    """

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError(f"payload must be bytes-like, got {type(payload).__name__}")
    blob = bytes(payload)
    if len(blob) < 5:
        raise ScanIdParseError(f"Scan identification payload too short: {len(blob)} bytes")

    manufacturer = blob[0]
    sw_bytes = blob[-4:-2]
    hw_bytes = blob[-2:]
    device_id_bytes = blob[1:-4]
    device_id = device_id_bytes.decode("ascii", errors="replace").rstrip("\x00").strip()

    return ScanIdentification(
        manufacturer=manufacturer,
        device_id=device_id,
        sw=sw_bytes.hex(),
        hw=hw_bytes.hex(),
    )


def parse_vaillant_scan_id_chunks(chunks: list[bytes]) -> VaillantScanId:
    """Parse Vaillant scan.id response chunks (B509 QQ=0x24..0x27).

    ebusd's `scan.csv` defines the scan-id as 4 chunks (QQ=0x24..0x27) of 8 bytes each,
    returned with a leading status byte. `EbusdTcpTransport` already strips the outer
    length prefix from `hex` responses, so each chunk is expected to be:

        <status:1> <ascii:8>
    """

    if len(chunks) != 4:
        raise VaillantScanIdParseError(f"Expected 4 chunks (0x24..0x27), got {len(chunks)}")

    raw_chunks = [bytes(chunk) for chunk in chunks]
    for chunk in raw_chunks:
        if len(chunk) < 9:
            raise VaillantScanIdParseError(
                f"Scan-id chunk too short: expected >=9 bytes, got {len(chunk)}"
            )

    # Variant A (legacy/documented in many setups):
    #   <status:1><ascii:8> for each QQ=0x24..0x27
    status_payload: bytes | None = None
    if all(chunk[0] == 0x00 for chunk in raw_chunks):
        status_payload = b"".join(chunk[1:9] for chunk in raw_chunks)

    # Variant B (observed on some VRC setups):
    #   9-byte chunk payload without a dedicated status byte; first chunk may start with 0x00,
    #   last chunk may be padded with 0xFF.
    raw9_payload = b"".join(chunk[:9] for chunk in raw_chunks)

    candidate_payloads: list[bytes] = []
    if status_payload is not None:
        candidate_payloads.append(status_payload)
    candidate_payloads.append(raw9_payload)

    for payload in candidate_payloads:
        raw = payload.strip(b"\x00\x20\xff").decode("ascii", errors="replace")
        if len(raw) < 28:
            continue

        prefix = raw[0:2]
        year = raw[2:4]
        week = raw[4:6]
        product = raw[6:16]
        supplier = raw[16:20]
        counter = raw[20:26]
        suffix = raw[26:28]

        return VaillantScanId(
            prefix=prefix,
            year=year,
            week=week,
            product=product,
            supplier=supplier,
            counter=counter,
            suffix=suffix,
            raw=raw,
        )

    raise VaillantScanIdParseError(
        "Scan-id string too short after normalization (expected >=28 chars)"
    )
