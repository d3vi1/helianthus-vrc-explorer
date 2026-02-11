from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .browse_models import BrowseTab, RegisterRow, TreeNodeRef
from .browse_store import BrowseStore


@dataclass(slots=True)
class _SearchState:
    query: str = ""
    matches: list[str | int] | None = None
    index: int = -1
    target: str = ""

    def __post_init__(self) -> None:
        if self.matches is None:
            self.matches = []


def _tab_id(tab: BrowseTab) -> str:
    return {
        "config": "tab-config",
        "config_limits": "tab-config-limits",
        "state": "tab-state",
    }[tab]


def _tab_from_id(tab_id: str) -> BrowseTab:
    if tab_id == "tab-config":
        return "config"
    if tab_id == "tab-config-limits":
        return "config_limits"
    return "state"


def run_browse_from_artifact(
    artifact: dict[str, object],
    *,
    allow_write: bool,
) -> None:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.screen import ModalScreen
    from textual.widgets import DataTable, Footer, Header, Input, Label, Static, Tab, Tabs, Tree

    class _FocusableStatic(Static):
        can_focus = True

    class _InputDialog(ModalScreen[str | None]):
        BINDINGS = [
            Binding("escape", "cancel", "Cancel"),
            Binding("enter", "submit", "Search"),
        ]
        CSS = """
        _InputDialog {
            align: center middle;
        }
        _InputDialog > Vertical {
            width: 70;
            padding: 1 2;
            border: heavy $accent;
            background: $surface;
        }
        """

        def __init__(self, *, title: str, value: str) -> None:
            super().__init__()
            self._title = title
            self._value = value

        def compose(self) -> ComposeResult:
            yield Vertical(Label(self._title), Input(value=self._value, id="value"))

        def on_mount(self) -> None:
            self.query_one(Input).focus()

        def action_cancel(self) -> None:
            self.dismiss(None)

        def action_submit(self) -> None:
            self.dismiss(self.query_one(Input).value.strip())

        def on_input_submitted(self, event: Input.Submitted) -> None:
            self.dismiss(event.value.strip())

    class _HelpDialog(ModalScreen[None]):
        BINDINGS = [Binding("escape", "close", "Close"), Binding("q", "close", "Close")]
        CSS = """
        _HelpDialog {
            align: center middle;
        }
        _HelpDialog > Vertical {
            width: 86;
            padding: 1 2;
            border: heavy $accent;
            background: $surface;
        }
        """

        def compose(self) -> ComposeResult:
            yield Vertical(
                Label("Browse Help"),
                Static(
                    "Tab/Shift+Tab focus | 1/2/3 tabs | Arrow keys navigate\n"
                    "/ search (focused widget) | n/N next/prev match\n"
                    "? help | q quit\n"
                    "W/P/R/E are reserved for watch/write flows (P1/P2)."
                ),
            )

        def action_close(self) -> None:
            self.dismiss(None)

    class _BrowseApp(App[None]):
        BINDINGS = [
            Binding("tab", "focus_next_section", "Next Focus"),
            Binding("shift+tab", "focus_prev_section", "Prev Focus"),
            Binding("1", "tab_config", "Config"),
            Binding("2", "tab_config_limits", "Config-Limits"),
            Binding("3", "tab_state", "State"),
            Binding("/", "search", "Search"),
            Binding("n", "search_next", "Next Match"),
            Binding("N", "search_prev", "Prev Match"),
            Binding("question_mark", "help", "Help"),
            Binding("e", "edit_selected", "Edit"),
            Binding("q", "quit", "Quit"),
            Binding("escape", "close_dialog", "Back"),
        ]

        CSS = """
        Screen {
            background: #2e3436;
            color: #eeeeec;
        }
        #main {
            height: 1fr;
        }
        #tree-pane {
            width: 35%;
            border: round #729fcf;
        }
        #right-pane {
            width: 65%;
            border: round #729fcf;
        }
        #watch-dock {
            height: 5;
            border: round #888a85;
        }
        #status {
            height: 1;
            padding: 0 1;
            color: #fce94f;
            background: #555753;
        }
        """

        def __init__(self) -> None:
            super().__init__()
            self._store = BrowseStore.from_artifact(artifact)
            self._node_by_id = {node.node_id: node for node in self._store.tree_nodes}
            self._tree_node_by_ref: dict[str, Any] = {}
            self._focus_order = ["tree", "tabs", "table", "watch"]
            self._focus_idx = 0
            self._selected_node_id = "root"
            self._active_tab: BrowseTab = "config"
            self._table_rows: list[RegisterRow] = []
            self._search = _SearchState()
            self._write_enabled = allow_write

        def compose(self) -> ComposeResult:
            yield Header(show_clock=False)
            with Horizontal(id="main"):
                with Vertical(id="tree-pane"):
                    yield Tree(self._store.device_label, id="browse-tree")
                with Vertical(id="right-pane"):
                    yield Tabs(
                        Tab("Config", id="tab-config"),
                        Tab("Config-Limits", id="tab-config-limits"),
                        Tab("State", id="tab-state"),
                        id="browse-tabs",
                    )
                    yield DataTable(id="browse-table")
            yield _FocusableStatic("Watchlist: reserved for P1 (watch/pin)", id="watch-dock")
            yield Static("", id="status")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#browse-table", DataTable)
            table.cursor_type = "row"
            table.add_columns(
                "Path/Name",
                "Address",
                "Value",
                "Raw",
                "Unit",
                "Access",
                "Last Update",
                "Age",
                "Δ",
            )
            self._build_tree()
            self._refresh_table()
            self._set_status("Ready")
            self._focus_tree()

        def _set_status(self, text: str) -> None:
            self.query_one("#status", Static).update(text)

        def _build_tree(self) -> None:
            tree = self.query_one("#browse-tree", Tree[str])
            tree.clear()
            root = tree.root
            root.data = "root"
            self._tree_node_by_ref = {"root": root}
            categories: dict[str, Any] = {}
            groups: dict[str, Any] = {}
            instances: dict[tuple[str, str], Any] = {}
            for node in self._store.tree_nodes:
                if node.level == "root":
                    continue
                if node.level == "category" and node.category_key is not None:
                    category_node = root.add(node.label, data=node.node_id)
                    categories[node.category_key] = category_node
                    self._tree_node_by_ref[node.node_id] = category_node
                    continue
                if node.level == "group" and node.category_key is not None:
                    parent = categories.get(node.category_key)
                    if parent is None:
                        continue
                    group_node = parent.add(node.label, data=node.node_id)
                    groups[node.group_key or ""] = group_node
                    self._tree_node_by_ref[node.node_id] = group_node
                    continue
                if (
                    node.level == "instance"
                    and node.group_key is not None
                    and node.instance_key is not None
                ):
                    parent = groups.get(node.group_key)
                    if parent is None:
                        continue
                    instance_node = parent.add(node.label, data=node.node_id)
                    instances[(node.group_key, node.instance_key)] = instance_node
                    self._tree_node_by_ref[node.node_id] = instance_node
                    continue
                if (
                    node.level == "register"
                    and node.group_key is not None
                    and node.instance_key is not None
                ):
                    parent = instances.get((node.group_key, node.instance_key))
                    if parent is None:
                        continue
                    register_node = parent.add(node.label, data=node.node_id)
                    self._tree_node_by_ref[node.node_id] = register_node
            root.expand()

        def _current_node(self) -> TreeNodeRef | None:
            return self._node_by_id.get(self._selected_node_id)

        def _refresh_table(self) -> None:
            table = self.query_one("#browse-table", DataTable)
            selected = self._current_node()
            self._table_rows = self._store.rows_for_selection(selected, tab=self._active_tab)
            cursor = max(0, table.cursor_row)
            table.clear(columns=False)
            for row in self._table_rows:
                table.add_row(
                    row.path,
                    row.address.label,
                    row.value_text,
                    row.raw_hex,
                    row.unit,
                    row.access_flags,
                    row.last_update_text,
                    row.age_text,
                    row.change_indicator,
                    key=row.row_id,
                )
            if self._table_rows:
                table.move_cursor(row=min(cursor, len(self._table_rows) - 1))
            status_text = (
                f"Rows: {len(self._table_rows)} | Selection: {self._selected_node_id} | "
                f"Tab: {self._active_tab}"
            )
            self._set_status(status_text)

        def _focus_tree(self) -> None:
            self.query_one("#browse-tree", Tree[str]).focus()
            self._focus_idx = 0

        def _focus_tabs(self) -> None:
            self.query_one("#browse-tabs", Tabs).focus()
            self._focus_idx = 1

        def _focus_table(self) -> None:
            self.query_one("#browse-table", DataTable).focus()
            self._focus_idx = 2

        def _focus_watch(self) -> None:
            self.query_one("#watch-dock", Static).focus()
            self._focus_idx = 3

        def _focus_by_index(self) -> None:
            match self._focus_order[self._focus_idx]:
                case "tree":
                    self._focus_tree()
                case "tabs":
                    self._focus_tabs()
                case "table":
                    self._focus_table()
                case _:
                    self._focus_watch()

        def action_focus_next_section(self) -> None:
            self._focus_idx = (self._focus_idx + 1) % len(self._focus_order)
            self._focus_by_index()

        def action_focus_prev_section(self) -> None:
            self._focus_idx = (self._focus_idx - 1) % len(self._focus_order)
            self._focus_by_index()

        def action_tab_config(self) -> None:
            self.query_one("#browse-tabs", Tabs).active = _tab_id("config")

        def action_tab_config_limits(self) -> None:
            self.query_one("#browse-tabs", Tabs).active = _tab_id("config_limits")

        def action_tab_state(self) -> None:
            self.query_one("#browse-tabs", Tabs).active = _tab_id("state")

        def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
            if event.tabs.id != "browse-tabs":
                return
            self._active_tab = _tab_from_id(event.tab.id or "tab-state")
            self._refresh_table()

        def on_tree_node_selected(self, event: Tree.NodeSelected[str]) -> None:
            data = event.node.data
            if isinstance(data, str):
                self._selected_node_id = data
                self._refresh_table()

        def action_search(self) -> None:
            target = self._focus_order[self._focus_idx]
            self._search.target = target
            self.push_screen(
                _InputDialog(title=f"Search in {target}", value=self._search.query),
                self._on_search_entered,
            )

        def _on_search_entered(self, query: str | None) -> None:
            if query is None:
                return
            q = query.strip().lower()
            self._search.query = q
            self._search.matches = []
            self._search.index = -1
            if not q:
                self._set_status("Search cleared")
                return

            if self._search.target == "tree":
                self._search.matches = [
                    node.node_id for node in self._store.tree_nodes if q in node.label.lower()
                ]
            else:
                self._search.matches = [
                    idx for idx, row in enumerate(self._table_rows) if q in row.search_blob
                ]
            if not self._search.matches:
                self._set_status(f"No matches for '{query}'")
                return
            self._search.index = 0
            self._apply_search_current()

        def _apply_search_current(self) -> None:
            if not self._search.matches or self._search.index < 0:
                return
            current = self._search.matches[self._search.index]
            if self._search.target == "tree":
                tree = self.query_one("#browse-tree", Tree[str])
                node = self._tree_node_by_ref.get(str(current))
                if node is not None:
                    parent = node.parent
                    while parent is not None:
                        parent.expand()
                        parent = parent.parent
                    tree.select_node(node)
                    self._focus_tree()
            else:
                table = self.query_one("#browse-table", DataTable)
                row = int(current)
                if 0 <= row < len(self._table_rows):
                    table.move_cursor(row=row)
                    self._focus_table()
            match_status = (
                f"Match {self._search.index + 1}/{len(self._search.matches)} "
                f"for '{self._search.query}'"
            )
            self._set_status(match_status)

        def action_search_next(self) -> None:
            if not self._search.matches:
                return
            self._search.index = (self._search.index + 1) % len(self._search.matches)
            self._apply_search_current()

        def action_search_prev(self) -> None:
            if not self._search.matches:
                return
            self._search.index = (self._search.index - 1) % len(self._search.matches)
            self._apply_search_current()

        def action_help(self) -> None:
            self.push_screen(_HelpDialog())

        def action_edit_selected(self) -> None:
            if not self._write_enabled:
                self._set_status("Write disabled: run with --allow-write")
                return
            self._set_status("Write flow is planned for P2 (not implemented in P0).")

        def action_close_dialog(self) -> None:
            if len(self.screen_stack) > 1:
                self.pop_screen()

    _BrowseApp().run()
