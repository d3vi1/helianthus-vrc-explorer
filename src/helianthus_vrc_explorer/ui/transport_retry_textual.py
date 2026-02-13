from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TransportRetrySettings:
    protocol: str
    host: str
    port: int


def run_transport_retry_modal(
    *,
    initial: TransportRetrySettings,
    error_message: str,
) -> TransportRetrySettings | None:
    """Interactive transport retry dialog for startup connection failures."""

    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Vertical
    from textual.widgets import Footer, Input, Label, RadioButton, RadioSet, Static

    class _TransportRetryApp(App[TransportRetrySettings | None]):
        BINDINGS = [
            Binding("enter", "retry", "Retry"),
            Binding("r", "retry", "Retry"),
            Binding("escape", "cancel", "Cancel"),
            Binding("q", "cancel", "Cancel"),
        ]
        CSS = """
        Screen {
            align: center middle;
            background: #2e3436;
            color: #eeeeec;
        }
        #dialog {
            width: 86;
            height: auto;
            padding: 1 2;
            border: heavy #729fcf;
            background: #202326;
        }
        #error {
            color: #ef2929;
            margin-bottom: 1;
        }
        #hint {
            color: #fce94f;
            margin-top: 1;
        }
        #status {
            color: #729fcf;
            margin-top: 1;
        }
        """

        def compose(self) -> ComposeResult:
            yield Vertical(
                Label("Transport retry"),
                Static(error_message, id="error"),
                Label("Protocol"),
                RadioSet(
                    RadioButton(
                        "ebusd TCP command port",
                        value=initial.protocol == "tcp",
                        id="proto-tcp",
                    ),
                    id="protocol",
                ),
                Label("Host"),
                Input(value=initial.host, id="host"),
                Label("Port"),
                Input(value=str(initial.port), id="port"),
                Static(
                    "Adjust settings then press Enter/R to retry. Esc/Q cancels.",
                    id="hint",
                ),
                Static("", id="status"),
                id="dialog",
            )
            yield Footer()

        def on_mount(self) -> None:
            host_input = self.query_one("#host", Input)
            host_input.focus()
            host_input.select_all()

        def _set_status(self, message: str) -> None:
            self.query_one("#status", Static).update(message)

        def action_cancel(self) -> None:
            self.exit(None)

        def action_retry(self) -> None:
            protocol_set = self.query_one("#protocol", RadioSet)
            selected = protocol_set.pressed_button
            protocol = "tcp" if selected is None else ("tcp" if selected.id == "proto-tcp" else "")
            if protocol != "tcp":
                self._set_status("Only TCP transport is currently supported.")
                return

            host = self.query_one("#host", Input).value.strip()
            if not host:
                self._set_status("Host is required.")
                return

            port_text = self.query_one("#port", Input).value.strip()
            try:
                port = int(port_text, 10)
            except ValueError:
                self._set_status(f"Invalid port: {port_text!r}")
                return
            if not (1 <= port <= 65535):
                self._set_status(f"Port out of range 1..65535: {port}")
                return

            self.exit(TransportRetrySettings(protocol=protocol, host=host, port=port))

        def on_input_submitted(self, _event: Input.Submitted) -> None:
            self.action_retry()

    return _TransportRetryApp().run()
