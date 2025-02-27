#!/usr/bin/env python3
"""
Created by Tanmay Patil
Copyright © 2025 Tanmay Patil. All rights reserved.

Main CLI tool for secure file encryption, key management, cryptographic extras, and ML-based optimization.
Features include animated feedback, dynamic processing messages, and a themed interactive menu.
"""

import argparse
import logging
import sys
import getpass
import time
import readline
import atexit
import glob
import os
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

# Assume these modules are implemented elsewhere.
from encryption import EncryptionHandler
from key_management import KeyManager
from utils import (
    setup_logging,
    AuditLogger,
    FileHandler,
    ProgressBar,
    create_backup,
    restore_from_backup,
    clean_up_backup,
    load_encryption_policy,
    apply_encryption_policy,
    start_metrics_server,
)
import crypto_extras
import performance_optimizer
import hyperparameter_tuner
import cryptanalysis
import compliance

# Rich UI imports for animations and styled output.
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
from rich.panel import Panel
from rich.live import Live

# Extended mapping for encryption algorithms.
ALGO_MAPPING = {
    "1": "AES",
    "2": "CHACHA20",
    "3": "POSTQUANTUM",   # Uses PyNaCl's SecretBox
    "4": "TWOFISH",
    "5": "CAMELLIA",
    "6": "AESGCM",
    "7": "RSAOAEP"
}

# Mapping for key generation types.
KEYGEN_MAPPING = {
    "1": "ECC",
    "2": "SYMMETRIC",
    "3": "PQ"
}

DEFAULT_ALGORITHM = "1"
DEFAULT_COMPRESS = False

def setup_readline():
    """Enable CLI history and file path auto-completion using readline."""
    history_file = Path.home() / ".cli_tool_history"
    try:
        readline.read_history_file(str(history_file))
    except FileNotFoundError:
        pass
    atexit.register(readline.write_history_file, str(history_file))
    readline.parse_and_bind("tab: complete")
    def completer(text, state):
        return (glob.glob(text + '*') + [None])[state]
    readline.set_completer(completer)

class EncryptionCLI:
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.file_handler = FileHandler()
        self.key_manager = KeyManager()
        self.console = Console()
        self.policy = None
        self.default_algorithm = DEFAULT_ALGORITHM
        self.default_compress = DEFAULT_COMPRESS

    def setup_argparse(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="Secure File Encryption CLI Tool with interactive menu and animated feedback"
        )
        parser.add_argument("action", nargs="?",
                            choices=["encrypt", "decrypt", "generate-key", "rotate-key", "extras", "ml"],
                            help="Action to perform")
        parser.add_argument("path", nargs="?",
                            help="Path of the file/folder (or base filename for key generation)")
        parser.add_argument("--output", "-o", help="Output path for processed files")
        parser.add_argument("--algorithm", "-a", choices=list(ALGO_MAPPING.keys()),
                            default=self.default_algorithm,
                            help="Encryption algorithm: " +
                                 ", ".join(f"{k}: {v}" for k, v in ALGO_MAPPING.items()))
        parser.add_argument("--compress", "-c", action="store_true", help="Compress file(s) before encryption")
        parser.add_argument("--recursive", "-r", action="store_true", help="Process directories recursively")
        parser.add_argument("--menu", action="store_true", help="Launch interactive menu")
        parser.add_argument("--policy", help="Path to JSON/YAML file containing encryption policy rules")
        parser.add_argument("--metrics", action="store_true", help="Start Prometheus metrics server on port 8000")
        parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                            default="INFO", help="Set logging level")
        parser.add_argument("--key-type", choices=list(KEYGEN_MAPPING.keys()), default="1",
                            help="Key generation type: " +
                                 ", ".join(f"{k}: {v}" for k, v in KEYGEN_MAPPING.items()))
        parser.add_argument("--chunk-size", type=int, help="Optional chunk size in bytes for file processing")
        return parser

    def get_password(self, prompt_text: str = "Enter password: ", confirm: bool = False) -> str:
        pwd = getpass.getpass(prompt_text)
        if confirm:
            pwd2 = getpass.getpass("Confirm password: ")
            if pwd != pwd2:
                raise ValueError("Passwords do not match!")
        return pwd

    def welcome_animation(self):
        """Animated welcome screen with text transitions."""
        for i in range(3, 0, -1):
            panel = Panel.fit(f"[bold cyan]Welcome to the Secure File Encryption Tool!\nStarting in {i}...",
                              border_style="bright_blue", padding=(1, 4))
            with Live(panel, refresh_per_second=4, transient=True):
                time.sleep(1)
        self.console.clear()

    def exit_animation(self):
        """Animated exit screen."""
        panel = Panel.fit("[bold green]Thank you for using the tool!\nGoodbye!",
                          border_style="bright_green", padding=(1, 4))
        with Live(panel, refresh_per_second=4, transient=True):
            time.sleep(2)
        self.console.clear()

    def process_file(self, action: str, file_path: str, output_path: Optional[str],
                     password: str, algo_choice: str, compress: bool, chunk_size: int = None) -> None:
        p = Path(file_path).resolve()
        if not p.is_file():
            raise ValueError(f"Input path is not a valid file: {file_path}")
        if output_path and not self.file_handler.validate_path(output_path):
            raise ValueError(f"Invalid output path: {output_path}")
        if not output_path:
            suffix = ".encrypted" if action in ("encrypt", "rotate-key") else ".decrypted"
            output_path = str(p.with_suffix(suffix))
        if self.policy:
            algo_choice = apply_encryption_policy(file_path, ALGO_MAPPING[algo_choice], self.policy)
        backup = None
        if Path(output_path).exists():
            backup = create_backup(output_path)
        try:
            # Show a dynamic processing message.
            with self.console.status(f"[bold green]{action.capitalize()}ing file: {p.name}...", spinner="dots"):
                if action == "encrypt":
                    EncryptionHandler.encrypt_file(file_path, output_path, password, ALGO_MAPPING[algo_choice], compress, chunk_size)
                elif action == "decrypt":
                    EncryptionHandler.decrypt_file(file_path, output_path, password, ALGO_MAPPING[algo_choice], compress, chunk_size)
                elif action == "rotate-key":
                    new_password = self.get_password("Enter new password: ", confirm=True)
                    EncryptionHandler.rotate_key_file(file_path, output_path, password, new_password, ALGO_MAPPING[algo_choice], compress, chunk_size)
            self.audit_logger.log_operation(action, file_path)
            if backup:
                clean_up_backup(backup)
        except Exception as e:
            if backup:
                restore_from_backup(backup, output_path)
            raise e

    def process_directory(self, action: str, dir_path: str, output_dir: Optional[str],
                          password: str, algo_choice: str, compress: bool, chunk_size: int = None) -> None:
        files = list(self.file_handler.walk_directory(dir_path))
        progress = ProgressBar(len(files), desc=f"{action.capitalize()}ing files")
        def task(file_path: Path):
            try:
                rel = file_path.relative_to(Path(dir_path))
                out = Path(output_dir) / rel if output_dir else file_path.with_suffix(
                    ".encrypted" if action in ("encrypt", "rotate-key") else ".decrypted")
                out.parent.mkdir(parents=True, exist_ok=True)
                self.process_file(action, str(file_path), str(out), password, algo_choice, compress, chunk_size)
                progress.update()
            except Exception as e:
                progress.update()
                self.console.print(f"[red]Error processing {file_path.name}: {e}[/red]")
        with ThreadPoolExecutor() as executor:
            list(executor.map(lambda fp: task(fp), files))
        progress.close()

    def file_operations_menu(self):
        """Interactive file operations with clear numbered choices and context-sensitive prompts."""
        while True:
            table = Table(title="[bold blue]File Operations[/bold blue]", border_style="blue")
            table.add_column("Option", justify="center", style="cyan", no_wrap=True)
            table.add_column("Action", style="magenta")
            table.add_row("1", "Encrypt File")
            table.add_row("2", "Decrypt File")
            table.add_row("3", "Encrypt Directory")
            table.add_row("4", "Decrypt Directory")
            table.add_row("5", "Rotate Key")
            table.add_row("6", "Back to Main Menu")
            self.console.print(table)
            choice = IntPrompt.ask("[bold green]Select an option (1-6)[/bold green]", choices=[str(i) for i in range(1,7)])
            if choice == 6:
                break
            if choice in (1, 2):
                act = "encrypt" if choice == 1 else "decrypt"
                fpath = Prompt.ask("Enter file path", default="Path to file")
                outpath = Prompt.ask("Enter output path (leave blank for default)", default="")
                algo_choice = Prompt.ask(f"Choose algorithm: " +
                                         ", ".join(f"{k}: {v}" for k, v in ALGO_MAPPING.items()) +
                                         f" (default: {self.default_algorithm})",
                                         choices=list(ALGO_MAPPING.keys()), default=self.default_algorithm)
                comp = Prompt.ask("Compress file? (yes/no)", choices=["yes", "no"], default="no")
                pwd = self.get_password(confirm=(act == "encrypt"))
                try:
                    self.process_file(act, fpath, outpath if outpath.strip() else None, pwd, algo_choice, comp == "yes")
                    self.console.print(f"[green]{act.capitalize()}ion successful for {Path(fpath).name}![/green]")
                except Exception as e:
                    self.console.print(f"[red]Error during {act}ion: {e}[/red]")
            elif choice in (3, 4):
                act = "encrypt" if choice == 3 else "decrypt"
                dpath = Prompt.ask("Enter directory path", default="Path to directory")
                outdir = Prompt.ask("Enter output directory (leave blank for default)", default="")
                algo_choice = Prompt.ask(f"Choose algorithm: " +
                                         ", ".join(f"{k}: {v}" for k, v in ALGO_MAPPING.items()) +
                                         f" (default: {self.default_algorithm})",
                                         choices=list(ALGO_MAPPING.keys()), default=self.default_algorithm)
                comp = Prompt.ask("Compress files? (yes/no)", choices=["yes", "no"], default="no")
                pwd = self.get_password(confirm=(act == "encrypt"))
                try:
                    self.process_directory(act, dpath, outdir if outdir.strip() else None, pwd, algo_choice, comp == "yes")
                    self.console.print(f"[green]{act.capitalize()}ion of directory successful![/green]")
                except Exception as e:
                    self.console.print(f"[red]Error during directory {act}ion: {e}[/red]")
            elif choice == 5:
                fpath = Prompt.ask("Enter file path for key rotation", default="Path to file")
                outpath = Prompt.ask("Enter output path (leave blank for default)", default="")
                algo_choice = Prompt.ask(f"Choose algorithm: " +
                                         ", ".join(f"{k}: {v}" for k, v in ALGO_MAPPING.items()) +
                                         f" (default: {self.default_algorithm})",
                                         choices=list(ALGO_MAPPING.keys()), default=self.default_algorithm)
                comp = Prompt.ask("Compress file? (yes/no)", choices=["yes", "no"], default="no")
                old_pwd = self.get_password(prompt_text="Enter current password: ")
                try:
                    self.process_file("rotate-key", fpath, outpath if outpath.strip() else None, old_pwd, algo_choice, comp == "yes")
                    self.console.print("[green]Key rotation successful![/green]")
                except Exception as e:
                    self.console.print(f"[red]Error during key rotation: {e}[/red]")

    def crypto_extras_menu(self):
        """Interactive cryptographic extras with live status messages."""
        while True:
            table = Table(title="[bold blue]Cryptographic Extras[/bold blue]", border_style="blue")
            table.add_column("Option", justify="center", style="cyan", no_wrap=True)
            table.add_column("Feature", style="magenta")
            table.add_row("1", "Sign file (Ed25519)")
            table.add_row("2", "Verify signature (Ed25519)")
            table.add_row("3", "Hash file (BLAKE2b)")
            table.add_row("4", "Hash file (SHAKE-256)")
            table.add_row("5", "Compute MAC (Poly1305)")
            table.add_row("6", "Password Hash (Argon2)")
            table.add_row("7", "Password Derivation (Scrypt)")
            table.add_row("8", "Generate X25519 key pair")
            table.add_row("9", "X25519 Key Exchange")
            table.add_row("10", "Threshold Signature (Placeholder)")
            table.add_row("11", "Back to Main Menu")
            self.console.print(table)
            choice = IntPrompt.ask("[bold green]Select an extras option (1-11)[/bold green]", choices=[str(i) for i in range(1,12)])
            if choice == 11:
                break
            elif choice == 1:
                filepath = Prompt.ask("Enter file path to sign", default="Path to file")
                with open(filepath, "rb") as f:
                    message = f.read()
                priv = Prompt.ask("Enter your Ed25519 private key (hex)")
                signature = crypto_extras.ed25519_sign(message, priv)
                self.console.print(f"[green]Signature (hex): {signature.hex()}[/green]")
            elif choice == 2:
                filepath = Prompt.ask("Enter file path to verify", default="Path to file")
                with open(filepath, "rb") as f:
                    message = f.read()
                sig_hex = Prompt.ask("Enter signature (hex)")
                pub = Prompt.ask("Enter Ed25519 public key (hex)")
                valid = crypto_extras.ed25519_verify(message, bytes.fromhex(sig_hex), pub)
                self.console.print(f"[green]Signature valid: {valid}[/green]")
            elif choice == 3:
                filepath = Prompt.ask("Enter file path to hash (BLAKE2b)", default="Path to file")
                with open(filepath, "rb") as f:
                    data = f.read()
                h = __import__("hashlib").blake2b(data).digest()
                self.console.print(f"[green]BLAKE2b hash (hex): {h.hex()}[/green]")
            elif choice == 4:
                filepath = Prompt.ask("Enter file path to hash (SHAKE-256)", default="Path to file")
                with open(filepath, "rb") as f:
                    data = f.read()
                digest = crypto_extras.shake256_hash(data, digest_size=64)
                self.console.print(f"[green]SHAKE-256 hash (hex): {digest.hex()}[/green]")
            elif choice == 5:
                filepath = Prompt.ask("Enter file path for MAC", default="Path to file")
                key_hex = Prompt.ask("Enter 32-byte key (hex) for Poly1305")
                with open(filepath, "rb") as f:
                    data = f.read()
                mac = crypto_extras.poly1305_mac(data, bytes.fromhex(key_hex))
                self.console.print(f"[green]Poly1305 MAC (hex): {mac.hex()}[/green]")
            elif choice == 6:
                password = Prompt.ask("Enter password")
                salt = os.urandom(16)
                hash_str = crypto_extras.argon2_hash(password, salt)
                self.console.print(f"[green]Argon2 hash: {hash_str}[/green]")
            elif choice == 7:
                password = Prompt.ask("Enter password")
                salt = os.urandom(16)
                derived = crypto_extras.scrypt_derive(password, salt)
                self.console.print(f"[green]Scrypt derived key (hex): {derived.hex()}[/green]")
            elif choice == 8:
                priv, pub = crypto_extras.generate_x25519_key_pair()
                self.console.print(f"[green]X25519 Private Key (hex): {priv.hex()}[/green]")
                self.console.print(f"[green]X25519 Public Key (hex): {pub.hex()}[/green]")
            elif choice == 9:
                priv_hex = Prompt.ask("Enter your X25519 private key (hex)")
                peer_pub_hex = Prompt.ask("Enter peer X25519 public key (hex)")
                shared = crypto_extras.x25519_derive_shared(bytes.fromhex(priv_hex), bytes.fromhex(peer_pub_hex))
                self.console.print(f"[green]Derived shared key (hex): {shared.hex()}[/green]")
            elif choice == 10:
                filepath = Prompt.ask("Enter file path to threshold sign", default="Path to file")
                with open(filepath, "rb") as f:
                    message = f.read()
                num_keys = IntPrompt.ask("Enter number of keys to combine", default=2)
                keys = []
                for i in range(num_keys):
                    key = Prompt.ask(f"Enter Ed25519 private key #{i+1} (hex)")
                    keys.append(key)
                signature = crypto_extras.threshold_sign(message, keys)
                self.console.print(f"[green]Threshold signature (hex): {signature.hex()}[/green]")
            else:
                self.console.print("[red]Invalid choice.[/red]")

    def key_management_menu(self):
        """Placeholder for key management features."""
        self.console.print("[yellow]Key management menu not implemented in this version.[/yellow]")

    def settings_menu(self):
        """Interactive settings menu with default value prompts and live feedback."""
        while True:
            table = Table(title="[bold blue]Settings[/bold blue]", border_style="blue")
            table.add_column("Option", justify="center", style="cyan", no_wrap=True)
            table.add_column("Setting", style="magenta")
            table.add_row("1", f"Default Algorithm: {ALGO_MAPPING[self.default_algorithm]}")
            table.add_row("2", f"Default Compression: {'Yes' if self.default_compress else 'No'}")
            table.add_row("3", "Back to Main Menu")
            self.console.print(table)
            choice = IntPrompt.ask("[bold green]Select a setting to change (1-3)[/bold green]", choices=["1", "2", "3"])
            if choice == 3:
                break
            elif choice == 1:
                new_algo = Prompt.ask("Choose default algorithm: " +
                                        ", ".join(f"{k}: {v}" for k, v in ALGO_MAPPING.items()),
                                        choices=list(ALGO_MAPPING.keys()),
                                        default=self.default_algorithm)
                self.default_algorithm = new_algo
                self.console.print(f"[green]Default algorithm set to: {ALGO_MAPPING[new_algo]}[/green]")
            elif choice == 2:
                new_comp = Prompt.ask("Enable compression by default? (yes/no)", choices=["yes", "no"], default="no")
                self.default_compress = (new_comp.lower() == "yes")
                self.console.print(f"[green]Default compression set to: {'Yes' if self.default_compress else 'No'}[/green]")

    def ml_menu(self):
        """Menu for ML-based optimization and tuning."""
        while True:
            table = Table(title="[bold blue]ML Optimization & Tuning[/bold blue]", border_style="blue")
            table.add_column("Option", justify="center", style="cyan", no_wrap=True)
            table.add_column("Feature", style="magenta")
            table.add_row("1", "Optimize Algorithm Selection (RL/Q-Learning)")
            table.add_row("2", "Hyperparameter Tuning (Bayesian Optimization)")
            table.add_row("3", "Run Cryptanalysis Simulation (Genetic Algorithm)")
            table.add_row("4", "Audit Log Anomaly Detection")
            table.add_row("5", "Back to Main Menu")
            self.console.print(table)
            choice = IntPrompt.ask("[bold green]Select an ML option (1-5)[/bold green]", choices=[str(i) for i in range(1,6)])
            if choice == 5:
                break
            elif choice == 1:
                self.console.print("[green]Optimizing algorithm selection using RL...[/green]")
                performance_optimizer.run_optimization()
            elif choice == 2:
                self.console.print("[green]Running hyperparameter tuning...[/green]")
                hyperparameter_tuner.run_tuning()
            elif choice == 3:
                self.console.print("[green]Running cryptanalysis simulation...[/green]")
                cryptanalysis.run_simulation()
            elif choice == 4:
                self.console.print("[green]Running audit log anomaly detection...[/green]")
                compliance.run_audit_analysis()
            else:
                self.console.print("[red]Invalid choice.[/red]")

    def main_menu(self):
        """Primary interactive main menu with persistent header and footer panels."""
        while True:
            table = Table(title="[bold blue]Main Menu[/bold blue]", border_style="blue")
            table.add_column("Section", justify="center", style="cyan", no_wrap=True)
            table.add_column("Action", style="magenta")
            table.add_row("1", "File Operations")
            table.add_row("2", "Key Management")
            table.add_row("3", "Cryptographic Extras")
            table.add_row("4", "Settings")
            table.add_row("5", "ML Optimization & Tuning")
            table.add_row("6", "Exit")
            self.console.print(table)
            choice = IntPrompt.ask("[bold green]Select a section (1-6)[/bold green]", choices=["1", "2", "3", "4", "5", "6"])
            if choice == 1:
                self.file_operations_menu()
            elif choice == 2:
                self.key_management_menu()
            elif choice == 3:
                self.crypto_extras_menu()
            elif choice == 4:
                self.settings_menu()
            elif choice == 5:
                self.ml_menu()
            elif choice == 6:
                break

    def interactive_menu(self):
        self.welcome_animation()
        self.main_menu()
        self.exit_animation()

    def run(self) -> int:
        setup_readline()  # Enable CLI history and auto-completion
        parser = self.setup_argparse()
        args = parser.parse_args()
        setup_logging(args.log_level)
        if args.metrics:
            start_metrics_server(8000)
        if args.policy:
            try:
                self.policy = load_encryption_policy(args.policy)
                logging.info("Encryption policy loaded successfully.")
            except Exception as e:
                logging.error(f"Failed to load encryption policy: {e}")
        if args.action == "extras" or args.menu:
            self.interactive_menu()
            return 0
        if args.action == "ml":
            self.ml_menu()
            return 0
        try:
            if not args.action or not args.path:
                raise ValueError("Missing required arguments. Use --menu for interactive mode.")
            if args.action in ["encrypt", "decrypt", "rotate-key"]:
                pwd = self.get_password(prompt_text="Enter password: ", confirm=(args.action != "decrypt"))
            algo_choice = args.algorithm if args.algorithm in ALGO_MAPPING else self.default_algorithm
            path = Path(args.path)
            # Pass args.chunk_size (can be None) to file/directory processing functions.
            if args.action == "generate-key":
                keygen_choice = args.key_type if args.key_type in KEYGEN_MAPPING else "1"
                if KEYGEN_MAPPING[keygen_choice] == "ECC":
                    pwd = self.get_password(prompt_text="Enter password for key encryption: ", confirm=True)
                    priv, pub = self.key_manager.generate_ecc_key_pair()
                    priv_path = path.with_suffix(".ecc.key")
                    pub_path = path.with_suffix(".ecc.pub")
                    self.key_manager.save_key(priv, str(priv_path), pwd)
                    self.key_manager.save_key(pub, str(pub_path))
                    self.console.print(f"[green]ECC key pair generated: {priv_path}, {pub_path}[/green]")
                elif KEYGEN_MAPPING[keygen_choice] == "SYMMETRIC":
                    sym_key = self.key_manager.generate_symmetric_key()
                    out_file = path.with_suffix(".sym.key")
                    with open(out_file, "w") as f:
                        f.write(sym_key.hex())
                    self.console.print(f"[green]Random symmetric key generated: {out_file}[/green]")
                elif KEYGEN_MAPPING[keygen_choice] == "PQ":
                    priv, pub = self.key_manager.generate_pq_key_pair()
                    priv_path = path.with_suffix(".pq.key")
                    pub_path = path.with_suffix(".pq.pub")
                    with open(priv_path, "w") as f:
                        f.write(priv.hex())
                    with open(pub_path, "w") as f:
                        f.write(pub.hex())
                    self.console.print(f"[green]PostQuantum key pair generated: {priv_path}, {pub_path}[/green]")
                else:
                    raise ValueError("Invalid key generation type.")
            elif path.is_file():
                self.process_file(args.action, str(path), args.output, pwd, algo_choice, args.compress, args.chunk_size)
            elif path.is_dir() and args.recursive:
                self.process_directory(args.action, str(path), args.output, pwd, algo_choice, args.compress, args.chunk_size)
            else:
                raise ValueError("For directories, please use the --recursive flag.")
            return 0
        except Exception as e:
            self.console.print(f"[red]Error: {e}[/red]")
            return 1

def main():
    cli = EncryptionCLI()
    sys.exit(cli.run())

if __name__ == "__main__":
    main()
