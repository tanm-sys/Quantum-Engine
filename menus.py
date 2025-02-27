from prompt_toolkit import Application, HTML, FormattedText
from prompt_toolkit.layout import Layout, HSplit, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import Frame, Label, TextArea
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.mouse_events import MouseEventTypes
from prompt_toolkit.formatted_text import FormattedText
from rich import print as rprint
from rich.panel import Panel
from rich.text import Text
import json
import os

# Configuration
CONFIG_FILE = "menu_config.json"
DEFAULT_THEME = {
    "primary": "#002b36",
    "secondary": "#586e75",
    "accent": "#2aa198",
    "highlight": "#93a1a1",
    "error": "#dc322f",
}

class AdvancedMenu:
    def __init__(self):
        self.theme = self.load_theme()
        self.menu_items = self.load_menu_items()
        self.selected_index = 0
        self.search_query = ""
        self.dragging = None
        self.layout = self.create_layout()
        self.key_bindings = self.create_key_bindings()
        self.app = Application(
            layout=self.layout,
            full_screen=True,
            mouse_support=True,
            style=self.create_style(),
            key_bindings=self.key_bindings,
        )

    def load_theme(self):
        # For now, return default theme
        return DEFAULT_THEME

    def create_style(self):
        return f"""
            .menu {{bg:{self.theme['primary']}; border: round;}}
            .title {{fg:{self.theme['accent']} bold}}
            .option {{fg:{self.theme['secondary']}}}
            .selected {{bg:{self.theme['highlight']} fg:{self.theme['primary']} bold}}
            .error {{fg:{self.theme['error']} bold}}
            .details {{fg:{self.theme['secondary']}}}
            .header {{bg:{self.theme['accent']} fg:white bold}}
            .footer {{bg:{self.theme['secondary']} fg:white}}
        """

    @property
    def filtered_items(self):
        if self.search_query:
            return [item for item in self.menu_items if self.search_query.lower() in item['name'].lower()]
        return self.menu_items

    def create_layout(self):
        header = Frame(
            Window(content=FormattedTextControl(text="Secure File Encryption Tool v1.0 - Main Menu"), height=1),
            style="class:header"
        )
        main_frame = Frame(
            Window(
                content=FormattedTextControl(
                    text=self.get_menu_text,
                    mouse_handler=self.mouse_handler
                ),
                height=lambda: len(self.filtered_items) + 2
            ),
            title="Main Menu",
            style="class:menu"
        )
        details_frame = Frame(
            Window(
                content=FormattedTextControl(self.get_details_text),
                height=10
            ),
            title="Details",
            style="class:menu"
        )
        footer = Frame(
            Window(content=FormattedTextControl(text="Press 'q' to exit | '/' to search"), height=1),
            style="class:footer"
        )
        return HSplit([header, main_frame, details_frame, footer])

    def create_key_bindings(self):
        kb = KeyBindings()

        @kb.add('up', 'k')
        def move_up(event):
            self.selected_index = max(0, self.selected_index - 1)

        @kb.add('down', 'j', 'tab')
        def move_down(event):
            self.selected_index = min(len(self.filtered_items) - 1, self.selected_index + 1)

        @kb.add('/')
        def focus_search(event):
            self.search_query = ""
            # A real implementation could shift focus to a search input widget

        @kb.add('enter', ' ')
        def select_item(event):
            if not self.filtered_items:
                return
            item = self.filtered_items[self.selected_index]
            if item.get('confirm'):
                self.show_confirmation_dialog()
            elif item.get('submenu'):
                self.open_submenu(item['submenu'])
            else:
                self.execute_action(item.get('action'))

        @kb.add('c-s')
        def save_config(event):
            self.save_menu_config()

        @kb.add('c-l')
        def load_config(event):
            self.load_menu_config()

        @kb.add('q')
        def exit_app(event):
            self.app.exit()

        return kb

    def mouse_handler(self, mouse_event):
        if mouse_event.event_type == MouseEventTypes.MOUSE_DOWN:
            self.dragging = mouse_event.position.y
        elif mouse_event.event_type == MouseEventTypes.MOUSE_UP:
            self.dragging = None
        elif self.dragging is not None:
            new_index = self.dragging + (mouse_event.position.y - self.dragging)
            if 0 <= new_index < len(self.menu_items):
                self.menu_items.insert(new_index, self.menu_items.pop(self.dragging))
                self.dragging = new_index

    def get_menu_text(self):
        menu = []
        for idx, item in enumerate(self.filtered_items):
            prefix = "▶ " if idx == self.selected_index else "  "
            style = "class:selected" if idx == self.selected_index else "class:option"
            menu.append((style, f"{prefix}{item['name']}\n"))
        return menu

    def get_details_text(self):
        if self.filtered_items:
            item = self.filtered_items[self.selected_index]
            details = item.get('description', "No details available")
            return FormattedText([
                ("class:details", f"{details}\n"),
                ("class:details", f"Shortcut: {item.get('shortcut', '')}\n")
            ])
        return FormattedText([("class:details", "Select an option for details")])

    def load_menu_items(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return [
                {"name": "File Operations", "action": "file_ops", "description": "Perform file encryption/decryption operations"},
                {"name": "Key Management", "action": "key_mgmt", "description": "Manage encryption keys"},
                {"name": "Cryptographic Extras", "action": "crypto_extras", "description": "Additional cryptographic operations"},
                {"name": "ML Optimization", "action": "ml_opt", "description": "Optimize encryption using ML"},
                {"name": "Settings", "action": "settings", "description": "Configure tool settings"},
                {"name": "Exit", "confirm": True, "description": "Exit the application"}
            ]

    def save_menu_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.menu_items, f)
        rprint(Panel.fit("[green]Menu configuration saved!"))

    def load_menu_config(self):
        try:
            with open(CONFIG_FILE, 'r') as f:
                self.menu_items = json.load(f)
                self.app.invalidate()
        except Exception as e:
            rprint(Panel.fit(f"[red]Error loading config: {str(e)}"))

    def show_confirmation_dialog(self):
        from prompt_toolkit.shortcuts import message_dialog
        result = message_dialog(
            title="Confirm Exit",
            text="Are you sure you want to exit?",
            buttons=[("Yes", True), ("No", False)]
        ).run()
        if result:
            self.app.exit()

    def open_submenu(self, submenu):
        # Implement submenu logic here
        rprint(Panel.fit(f"[yellow]Opening submenu: {submenu}"))

    def execute_action(self, action):
        # Implement action execution here
        rprint(Panel.fit(f"[cyan]Executing action: {action}"))

    def run(self):
        self.app.run()

def main():
    menu = AdvancedMenu()
    menu.run()

if __name__ == "__main__":
    main()
