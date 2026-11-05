import asyncio, sys, logging
from slixmpp import ClientXMPP
logging.basicConfig(level=logging.ERROR)
DOMAIN="murknet.htb"; HOST="10.129.4.51"; PORT=5222
USER=sys.argv[1] if len(sys.argv)>1 else "watsonir"
PW=sys.argv[2] if len(sys.argv)>2 else "Sherlock2026!"

class Reg(ClientXMPP):
    def __init__(self):
        super().__init__(f"{USER}@{DOMAIN}", PW)
        self.register_plugin('xep_0030'); self.register_plugin('xep_0077')
        self.plugin['xep_0077'].force_registration = True
        self.add_event_handler("register", self.do_register)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("failed_auth", lambda e: print("[-] auth failed"))
        import ssl
        self.ssl_context.check_hostname=False
        self.ssl_context.verify_mode=ssl.CERT_NONE
        self.done=asyncio.Event()
    async def do_register(self, iq):
        resp = self.Iq(); resp['type']='set'
        resp['register']['username']=USER; resp['register']['password']=PW
        try:
            await resp.send(); print(f"[+] REGISTERED {USER}@{DOMAIN} / {PW}")
        except Exception as e:
            print(f"[-] register error: {e}"); self.done.set()
    async def start(self, ev):
        print(f"[+] AUTHENTICATED as {USER}@{DOMAIN}")
        self.disconnect(); self.done.set()

async def main():
    x=Reg(); x.add_event_handler("disconnected", lambda e: x.done.set())
    x.connect(HOST, PORT)
    try: await asyncio.wait_for(x.done.wait(), timeout=35)
    except asyncio.TimeoutError: print("[-] timeout")
asyncio.run(main())
