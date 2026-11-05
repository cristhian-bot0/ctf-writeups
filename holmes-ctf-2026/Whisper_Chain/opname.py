import asyncio, ssl, logging, base64, subprocess
from slixmpp import ClientXMPP
from slixmpp.xmlstream import tostring
logging.basicConfig(level=logging.CRITICAL)
HOST="10.129.4.69"; PORT=5222
JID="zytglogge88@murknet.htb"; PW="TickTock24!"
SVC="command.murknet.htb"
KEYS={"op_snatch":"SHALLOWBLUE","op_sparkling":"BLACKFENLOTTE"}

def dec(b64,key):
    try:
        raw=base64.b64decode(b64)
        p=subprocess.run(["openssl","enc","-d","-aes-256-cbc","-pbkdf2","-iter","120000","-md","sha256","-pass",f"pass:{key}"],
                         input=raw,capture_output=True,timeout=15)
        return p.stdout.decode(errors="replace") if p.returncode==0 else f"[fail {p.stderr.decode(errors='replace')[:80]}]"
    except Exception as e: return f"[err {e}]"

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
        disco=self.plugin['xep_0030']; ps=self.plugin['xep_0060']
        # 1) discover all nodes on the service
        print("="*70,"\n# ALL NODES ON",SVC,"\n","="*70)
        nodes=[]
        try:
            res=await disco.get_items(jid=SVC, timeout=20)
            for it in res['disco_items']['items']:
                nodes.append(it[1]); print(f"  node={it[1]!r}  name={it[2]!r}")
        except Exception as e: print("[disco items err]",e)
        for n in KEYS:
            if n not in nodes: nodes.append(n)
        # 2) per node: config/meta (title+description) + items
        for node in nodes:
            print("\n"+"="*70,f"\n# NODE {node}\n","="*70)
            try:
                info=await disco.get_info(jid=SVC, node=node, timeout=20)
                for f in info['disco_info'].get_fields():
                    var=f.get('var'); val=f.get_value()
                    if var and ('title' in var or 'description' in var or 'type' in var):
                        print(f"  META {var} = {val!r}")
                print("  RAW-INFO:", tostring(info['disco_info'].xml)[:800])
            except Exception as e: print("  [info err]",e)
            try:
                res=await ps.get_items(SVC, node, timeout=25)
                for it in res['pubsub']['items']:
                    print(f"\n  --- item id={it['id']} ---")
                    pl=it['payload']
                    txt = pl.text if pl is not None and pl.text else (tostring(pl) if pl is not None else "")
                    print("  payload:", (txt or "")[:200])
                    if txt and "U2FsdGVk" in txt:
                        k=KEYS.get(node)
                        if k: print("  DECRYPT:",dec(txt.strip(),k))
                        else:
                            for kk in set(KEYS.values()):
                                print(f"  DECRYPT[{kk}]:",dec(txt.strip(),kk))
            except Exception as e: print("  [items err]",e)
        self.disconnect(); self.done.set()

async def main():
    x=P(); x.add_event_handler("disconnected", lambda e:x.done.set())
    x.connect(HOST,PORT)
    try: await asyncio.wait_for(x.done.wait(), timeout=120)
    except asyncio.TimeoutError: print("[-] timeout")
asyncio.run(main())
