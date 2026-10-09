"""Optional real-Xray loopback interoperability test; requires an Xray executable."""
import asyncio, json, os, socket, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
for key in ('ALL_PROXY','HTTPS_PROXY','HTTP_PROXY','all_proxy','https_proxy','http_proxy'):os.environ.pop(key,None)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='xray-test-')
os.environ['ALLOW_PRIVATE_DESTINATIONS'] = '1'
os.environ['ADMIN_PASSWORD'] = 'xray-local-test-only'
import main, uvicorn, httpx

def reserve():
 s=socket.socket();s.bind(('127.0.0.1',0));s.listen(128);return s

async def run():
 sock=reserve();port=sock.getsockname()[1]
 server=uvicorn.Server(uvicorn.Config(main.app,log_level='error'))
 task=asyncio.create_task(server.serve(sockets=[sock]))
 while not server.started:await asyncio.sleep(.01)
 uid,_=await main.make_link(label='xray-test')
 payload=os.urandom(1024*1024)
 async def target(reader,writer):
  await reader.readuntil(b'\r\n\r\n')
  writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(payload)).encode()+b'\r\nConnection: close\r\n\r\n'+payload)
  await writer.drain();writer.close();await writer.wait_closed()
 upstream=await asyncio.start_server(target,'127.0.0.1',0)
 target_port=upstream.sockets[0].getsockname()[1]
 try:
  for network in ('ws','xhttp'):
   ps=reserve();proxy_port=ps.getsockname()[1];ps.close()
   transport={'network':network,'security':'none'}
   if network=='ws':transport['wsSettings']={'path':f'/ws/{uid}'}
   else:transport['xhttpSettings']={'path':f'/xhttp-siz10/{uid}','mode':'packet-up'}
   config={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':proxy_port,'protocol':'http'}], 'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':port,'users':[{'id':uid,'encryption':'none'}]}]},'streamSettings':transport}]}
   path=Path(os.environ['DATA_DIR'])/f'{network}.json';path.write_text(json.dumps(config))
   log=open(f'/tmp/xray-{network}.log','w')
   proc=await asyncio.create_subprocess_exec(os.environ.get('XRAY_BINARY', 'xray'),'run','-config',str(path),stdout=log,stderr=log)
   try:
    for _ in range(100):
     try:
      r,w=await asyncio.open_connection('127.0.0.1',proxy_port);w.close();await w.wait_closed();break
     except OSError:await asyncio.sleep(.02)
    async with httpx.AsyncClient(proxy=f'http://127.0.0.1:{proxy_port}',timeout=20,trust_env=False) as client:
     for i in range(5):
      response=await client.get(f'http://127.0.0.1:{target_port}/test')
      assert response.content==payload,(network,len(response.content))
    print(f'{network}: Xray 26.3.27, 5 x 1 MiB HTTP downloads, bytes match',flush=True)
   finally:
    proc.terminate();await proc.wait();log.close()
 finally:
  upstream.close();await upstream.wait_closed();server.should_exit=True;await task
asyncio.run(run())
