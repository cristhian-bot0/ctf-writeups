import asyncio, ssl, logging
from slixmpp import ClientXMPP
logging.basicConfig(level=logging.ERROR)
DOMAIN="murknet.htb"; HOST="10.129.4.51"; PORT=5222
USER="watsonir"; PW="Sherlock2026!"; NICK="watsonir"
ROOMS=["rules","resources","infra","random"]

class M(ClientXMPP):
    def __init__(self):
        super().__init__(f"{USER}@{DOMAIN}", PW)
        for p in ['xep_0030','xep_0045','xep_0313','xep_0199','xep_0059']:
            self.register_plugin(p)
        self.ssl_context.check_hostname=False; self.ssl_context.verify_mode=ssl.CERT_NONE
        self.add_event_handler("session_start", self.start)
        self.done=asyncio.Event()
    async def start(self, ev):
        self.send_presence(); await self.get_roster()
        mam=self.plugin['xep_0313']
        for r in ROOMS:
            room=f"{r}@groups.murknet.htb"
            print(f"\n{'='*70}\n# ROOM {room}\n{'='*70}")
            try:
                await self.plugin['xep_0045'].join_muc(room, NICK, timeout=15)
            except Exception as e:
                print(f"[join err] {e}")
            try:
                results=[]
                async for msg in mam.iterate(jid=room, reverse=False):
                    results.append(msg)
                print(f"[{len(results)} archived]")
                for fwd in results:
                    try:
                        m=fwd['mam_result']['forwarded']['stanza']
                        d=fwd['mam_result']['forwarded']['delay']['stamp']
                    except Exception:
                        m=fwd; d=""
                    frm=m['from']; body=m['body']
                    if body:
                        print(f"[{d}] <{frm}> {body}")
            except Exception as e:
                print(f"[mam err] {e}")
        self.disconnect(); self.done.set()

async def main():
    x=M(); x.add_event_handler("disconnected", lambda e:x.done.set())
    x.connect(HOST,PORT)
    try: await asyncio.wait_for(x.done.wait(), timeout=120)
    except asyncio.TimeoutError: print("[-] timeout")
asyncio.run(main())
