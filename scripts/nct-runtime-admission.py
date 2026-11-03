"""Nonmutating pre-install runtime test, executed inside the exact loaded image."""
import asyncio
import importlib.metadata
import json
import sqlite3
import subprocess
import sys
import threading

thread=threading.Thread(target=lambda:None)
thread.start();thread.join(timeout=5)
if thread.is_alive():raise RuntimeError('Runtime thread did not finish')
asyncio.run(asyncio.sleep(0))
import fastapi
import pydantic
import uvicorn
with sqlite3.connect(':memory:') as db:
    assert db.execute("SELECT json_extract('{\"ready\":1}','$.ready')").fetchone()[0]==1
versions={name:importlib.metadata.version(name) for name in ('fastapi','pydantic','uvicorn')}
if sys.argv[1:]==['app']:
    import defusedxml
    import python_multipart
    for command in (['nmap','--version'],['fping','-v'],['tcpdump','--version'],['ssh','-V'],['script','--version']):
        result=subprocess.run(command,capture_output=True,text=True,timeout=10)
        if result.returncode:raise RuntimeError('Required collection tool failed: '+command[0])
print(json.dumps({'runtime_admission':'pass','image_kind':sys.argv[1:],'versions':versions}))
