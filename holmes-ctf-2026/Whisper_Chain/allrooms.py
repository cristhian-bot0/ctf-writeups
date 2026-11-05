import asyncio, ssl, logging
from slixmpp import ClientXMPP
from slixmpp.xmlstream import tostring
logging.basicConfig(level=logging.CRITICAL)
DOMAIN="murknet.htb"; HOST="10.129.4.69"; PORT=5222
JID="zytglogge88@murknet.htb"; PW="TickTock24!"; NICK="swissclock"

class M(ClientXMPP):
    def __init__(self):
        super().__init__(JID, PW)
        for p in ['xep_0030','xep_0045','xep_0313','xep_0199','xep_0059']:
            self.register_plugin(p)
        self.ssl_context.check_hostname=False; self.ssl_context.verify_mode=ssl.CERT_NONE
        self.add_event_handler("session_start", self.start)
        self.done=asyncio.Event()
    async def start(self, ev):
        self.send_presence(); await self.get_roster()
        disco=self.plugin['xep_0030']; mam=self.plugin['xep_0313']
        # roster
        print("### ROSTER ###")
        for j in self.client_roster:
            print("  ",j)
        # all MUC rooms
        print("\n### ALL ROOMS on groups.murknet.htb ###")
        rooms=[]
        try:
            res=await disco.get_items(jid="groups.murknet.htb", timeout=20)
            for it in res['disco_items']['items']:
                rooms.append(it[0]); print("  room=",it[0]," name=",it[2])
        except Exception as e: print("  [err]",e)
        # all pubsub nodes
        print("\n### PUBSUB nodes on command.murknet.htb ###")
        try:
            res=await disco.get_items(jid="command.murknet.htb", timeout=20)
            for it in res['disco_items']['items']:
                print("  node=",it[1]," name=",it[2])
        except Exception as e: print("  [err]",e)
        # DMs: dump MAM for the whole account (no with_jid = everything), then per peer
        peers=set()
        for j in self.client_roster: peers.add(str(j))
        peers.update([f"{n}@{DOMAIN}" for n in ["snake6288","doctor9091","spurio9","dang","colonel","venom","timothy","snowwhite","dynamite","spur"]])
        for pj in sorted(peers):
            print(f"\n### DM {pj} ###")
            try:
                n=0
                async for msg in mam.iterate(with_jid=pj, reverse=False):
                    try:
                        m=msg['mam_result']['forwarded']['stanza']
                        d=msg['mam_result']['forwarded']['delay']['stamp']
                    except Exception:
                        m=msg; d=""
                    body=m['body']; frm=m['from']
                    if body: print(f"  [{d}] <{frm}> {body}"); n+=1
                if n: print(f"  [{n} msgs]")
            except Exception as e: print("  [err]",e)
        self.disconnect(); self.done.set()

async def main():
    x=M(); x.add_event_handler("disconnected", lambda e:x.done.set())
    x.connect(HOST,PORT)
    try: await asyncio.wait_for(x.done.wait(), timeout=150)
    except asyncio.TimeoutError: print("[-] timeout")
asyncio.run(main())
