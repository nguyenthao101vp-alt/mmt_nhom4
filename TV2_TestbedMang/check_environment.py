import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent

def check_command(name, args):
    path=shutil.which(name)
    if not path:
        return {"available": False, "path": None, "version": None, "error": "Not found in PATH"}
    try:
        proc=subprocess.run([path,*args],capture_output=True,text=True,timeout=8)
        output=(proc.stdout or proc.stderr).strip()
        return {"available": proc.returncode==0,"path":path,"version":output.splitlines()[0] if output else None,"error":None if proc.returncode==0 else f"Exit code {proc.returncode}: {output[:200]}"}
    except (OSError,subprocess.TimeoutExpired) as exc:
        return {"available":False,"path":path,"version":None,"error":str(exc)}

def main():
    try:
        config=json.loads((ROOT/'config.json').read_text(encoding='utf-8'))
        network=config['network']
        assert network['default_bandwidth_mbps'] in network['bandwidth_profiles_mbps']
        assert 0<=network['loss_percent']<=100
        assert network['delay_ms']>=0
        assert 1<=network['tcp_port']<=65535
    except (OSError,ValueError,KeyError,TypeError,AssertionError) as exc:
        print(f"Configuration invalid: {exc}")
        return 2
    specs={"mininet":('mn',['--version']),"ffmpeg":('ffmpeg',['-version']),"ffprobe":('ffprobe',['-version']),"iperf3":('iperf3',['--version']),"tc":('tc',['-V']),"tcpdump":('tcpdump',['--version'])}
    tools={key:check_command(*args) for key,args in specs.items()}
    is_linux=sys.platform.startswith('linux')
    is_root=hasattr(os,'geteuid') and os.geteuid()==0
    ready=is_linux and is_root and all(item['available'] for item in tools.values())
    print(f"OS: {platform.platform()}")
    print(f"Python: {platform.python_version()}")
    print(f"Linux: {is_linux}; root: {is_root}")
    for name,result in tools.items():
        print(f"{name}: {'OK' if result['available'] else 'MISSING/ERROR'} | {result['version'] or result['error']}")
    print(f"Prerequisite check: {'PASS' if ready else 'INCOMPLETE'}")
    print('Mininet functional test: NOT RUN (requires separate sudo mn --test pingall on Ubuntu VM)')
    return 0 if ready else 1

if __name__=='__main__':
    sys.exit(main())
