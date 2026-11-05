import asyncio, ssl, logging
from slixmpp import ClientXMPP
logging.basicConfig(level=logging.CRITICAL)
HOST="10.129.4.51"; PORT=5222
JID="zytglogge88@murknet.htb"; PW="TickTock24!"; NICK="swissclock"

class S(ClientXMPP):
    def __init__(self):
        super().__init__(JID, PW)
        for p in ['xep_0030','xep_0045','xep_0060','xep_0313','xep_0059']:
            self.register_plugin(p)
        self.ssl_context.check_hostname=False; self.ssl_context.verify_mode=ssl.CERT_NONE
        self.add_event_handler("session_start", self.start)
        self.done=asyncio.Event()
    async def start(self, ev):
        self.send_presence()
        await self.get_roster()
        print("### ROSTER:")
        for j in self.client_roster:
            print("   ", j, self.client_roster[j]['name'], self.client_roster[j]['subscription'])
        # disco items on command + groups + server
        for tgt in ["command.murknet.htb","groups.murknet.htb","murknet.htb","pubsub.murknet.htb"]:
            print(f"\n### DISCO ITEMS {tgt}")
            try:
                items=await self.plugin['xep_0030'].get_items(jid=tgt, timeout=12)
                for it in items['disco_items']['items']:
                    print("   ITEM", it[0], "node=",it[1], "name=",it[2])
            except Exception as e:
                print("   ERR", e)
            print(f"### DISCO INFO {tgt}")
            try:
                info=await self.plugin['xep_0030'].get_info(jid=tgt, timeout=12)
                idents=[(i[0],i[1],i[2]) for i in info['disco_info']['identities']]
                print("   identities:", idents)
            except Exception as e:
                print("   ERR", e)
        # personal MAM (own DMs)
        print("\n### PERSONAL MAM (DMs)")
        try:
            n=0
            async for msg in self.plugin['xep_0313'].iterate():
                try:
                    m=msg['mam_result']['forwarded']['stanza']
                    d=msg['mam_result']['forwarded']['delay']['stamp']
                    if m['body']:
                        print(f"[{d}] {m['from']} -> {m['to']}: {m['body']}"); n+=1
                except Exception as e:
                    pass
            print(f"[{n} personal msgs]")
        except Exception as e:
            print("   MAM ERR", e)
        self.disconnect(); self.done.set()

async def main():
    x=S(); x.add_event_handler("disconnected", lambda e:x.done.set())
    x.connect(HOST,PORT)
    try: await asyncio.wait_for(x.done.wait(), timeout=90)
    except asyncio.TimeoutError: print("[-] timeout")
asyncio.run(main())
