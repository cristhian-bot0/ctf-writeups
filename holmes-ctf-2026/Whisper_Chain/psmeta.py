import asyncio, ssl, logging
from slixmpp import ClientXMPP
from slixmpp.xmlstream import tostring, ET
logging.basicConfig(level=logging.CRITICAL)
HOST="10.129.4.51"; PORT=5222
JID="zytglogge88@murknet.htb"; PW="TickTock24!"
SVC="command.murknet.htb"

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
        # try many candidate node names
        for node in ["op_snatch","op_sparkling","keys","decryptor","instructions","key","directives","op_whisper","whisper"]:
            try:
                # raw items request to see full xml with attributes
                iq=self.Iq(); iq['type']='get'; iq['to']=SVC
                iq['pubsub']['items']['node']=node
                res=await iq.send(timeout=15)
                items=res['pubsub']['items']
                print(f"\n### NODE {node}: {len(list(items))} items")
                for it in items:
                    print("  RAW:", tostring(it.xml)[:400])
            except Exception as e:
                se=str(e)[:50]
                if 'item-not-found' not in se:
                    print(f"### NODE {node}: ERR {se}")
        # node config/meta for op_snatch
        for node in ["op_snatch","op_sparkling"]:
            try:
                info=await self.plugin['xep_0030'].get_info(jid=SVC, node=node, timeout=12)
                print(f"\n### META {node}:")
                for f in info['disco_info']['features']: pass
                x=info['disco_info']
                print("  ", tostring(x.xml)[:600])
            except Exception as e:
                print(f"### META {node} ERR {str(e)[:50]}")
        self.disconnect(); self.done.set()

async def main():
    x=P(); x.add_event_handler("disconnected", lambda e:x.done.set())
    x.connect(HOST,PORT)
    try: await asyncio.wait_for(x.done.wait(), timeout=80)
    except asyncio.TimeoutError: print("[-] timeout")
asyncio.run(main())
