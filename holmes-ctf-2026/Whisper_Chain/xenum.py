import asyncio, ssl, logging
from slixmpp import ClientXMPP
logging.basicConfig(level=logging.ERROR)
DOMAIN="murknet.htb"; HOST="10.129.4.51"; PORT=5222
USER="watsonir"; PW="Sherlock2026!"

class E(ClientXMPP):
    def __init__(self):
        super().__init__(f"{USER}@{DOMAIN}", PW)
        for p in ['xep_0030','xep_0045','xep_0060','xep_0199']:
            self.register_plugin(p)
        self.ssl_context.check_hostname=False; self.ssl_context.verify_mode=ssl.CERT_NONE
        self.add_event_handler("session_start", self.start)
        self.done=asyncio.Event()
    async def start(self, ev):
        self.send_presence(); 
        # disco items on server + known vhosts
        for tgt in [DOMAIN, "groups.murknet.htb", "command.murknet.htb", "upload.murknet.htb"]:
            try:
                info = await self['xep_0030'].get_info(jid=tgt, timeout=10)
                ids=[(i['category'],i['type'],i['name']) for i in info['disco_info']['identities']]
                feats=list(info['disco_info']['features'])
                print(f"\n### INFO {tgt}: ids={ids}")
            except Exception as e:
                print(f"\n### INFO {tgt}: ERR {e}"); ids=[]
            try:
                items = await self['xep_0030'].get_items(jid=tgt, timeout=10)
                for it in items['disco_items']['items']:
                    print(f"   ITEM {tgt} -> {it[0]}  node={it[1]}  name={it[2]}")
            except Exception as e:
                print(f"   ITEMS {tgt}: ERR {e}")
        # roster
        try:
            await self.get_roster()
            print("\n### ROSTER:", list(self.client_roster.keys()))
        except Exception as e:
            print("roster err", e)
        self.disconnect(); self.done.set()

async def main():
    x=E(); x.add_event_handler("disconnected", lambda e: x.done.set())
    x.connect(HOST,PORT)
    try: await asyncio.wait_for(x.done.wait(), timeout=60)
    except asyncio.TimeoutError: print("[-] timeout")
asyncio.run(main())
