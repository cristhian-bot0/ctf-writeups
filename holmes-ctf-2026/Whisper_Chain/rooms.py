import asyncio, ssl, logging
from slixmpp import ClientXMPP
from slixmpp.xmlstream import tostring
logging.basicConfig(level=logging.CRITICAL)
DOMAIN="murknet.htb"; HOST="10.129.4.69"; PORT=5222
JID="zytglogge88@murknet.htb"; PW="TickTock24!"; NICK="swissclock"
# members-only + public, in case objective stated anywhere
ROOMS=["op_snatch","op_sparkling","rules","resources","infra","random"]
DM_PEERS=["snake6288","doctor9091","spurio9","dang"]

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
        disco=self.plugin['xep_0030']; muc=self.plugin['xep_0045']; mam=self.plugin['xep_0313']
        for r in ROOMS:
            room=f"{r}@groups.murknet.htb"
            print(f"\n{'='*70}\n# ROOM {room}\n{'='*70}")
            try:
                info=await disco.get_info(jid=room, timeout=15)
                print("  DISCO:", tostring(info['disco_info'].xml)[:900])
            except Exception as e: print("  [disco err]",e)
            try:
                await muc.join_muc(room, NICK, timeout=15)
                subj = muc.rooms.get(room, {})
                print("  (joined)")
            except Exception as e:
                print(f"  [join err] {e}")
            try:
                n=0
                async for msg in mam.iterate(jid=room, reverse=False):
                    try:
                        m=msg['mam_result']['forwarded']['stanza']
                        d=msg['mam_result']['forwarded']['delay']['stamp']
                    except Exception:
                        m=msg; d=""
                    body=m['body']; frm=m['from']
                    subj=m['subject'] if 'subject' in m.keys() else None
                    if subj: print(f"  [SUBJECT] {subj}")
                    if body: print(f"  [{d}] <{frm}> {body}"); n+=1
                print(f"  [{n} msgs]")
            except Exception as e: print("  [mam err]",e)
        # DMs
        for peer in DM_PEERS:
            pj=f"{peer}@{DOMAIN}"
            print(f"\n{'#'*70}\n# DM with {pj}\n{'#'*70}")
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
                print(f"  [{n} msgs]")
            except Exception as e: print("  [dm mam err]",e)
        self.disconnect(); self.done.set()

async def main():
    x=M(); x.add_event_handler("disconnected", lambda e:x.done.set())
    x.connect(HOST,PORT)
    try: await asyncio.wait_for(x.done.wait(), timeout=150)
    except asyncio.TimeoutError: print("[-] timeout")
asyncio.run(main())
