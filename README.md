# portscanner
Simple TCP port scanner with banner grabbing.
```bash
python portscanner.py localhost
python portscanner.py example.com -p 80,443,8080
python portscanner.py 10.0.0.1 -p 1-1024 --banner -w 100
```
## Zero dependencies. Python 3.6+.
