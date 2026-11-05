import asyncio, ssl, logging
from slixmpp import ClientXMPP
from slixmpp.xmlstream import tostring
logging.basicConfig(level=logging.CRITICAL)
HOST="10.129.4.51"; PORT=5222
JID="zytglogge88@murknet.htb"; PW="TickTock24!"
SVC="command.murknet.htb"; NODES=["op_snatch","op_sparkling"]

class P(ClientXMPP):
    def __init__(self):
        super().__init__(JID, PW)
        for p in ['xep_0030','xep_0060']:
            self.register_plugin(p)
        self.ssl_context.check_hostname=False; self.ssl_context.verify_mode=ssl.CERT_NONE
        self.add_event_handler("session_start", self.start)
        self.done=asyncio.Event()
    async def start(self, ev):
        self.send_presence()
        ps=self.plugin['xep_0060']
        for node in NODES:
            print(f"\n{'='*70}\n# NODE {node}\n{'='*70}")
            # try disco info/items on node
            try:
                res=await ps.get_items(SVC, node, timeout=20)
                items=res['pubsub']['items']
                cnt=0
                for it in items:
                    cnt+=1
                    print(f"\n--- item id={it['id']} ---")
                    payload=it['payload']
                    if payload is not None:
                        print(tostring(payload))
                    else:
                        print(tostring(it.xml))
                print(f"\n[{cnt} items in {node}]")
            except Exception as e:
                print(f"[get_items err] {e}")
        self.disconnect(); self.done.set()

async def main():
    x=P(); x.add_event_handler("disconnected", lambda e:x.done.set())
    x.connect(HOST,PORT)
    try: await asyncio.wait_for(x.done.wait(), timeout=90)
    except asyncio.TimeoutError: print("[-] timeout")
asyncio.run(main())
