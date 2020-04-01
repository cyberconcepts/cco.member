#user_post.sh

url="http://localhost:11080/sites/steg/views/webapi/users"  # local dev
#url="http://fms.steg.cy55.de/api/users"  # STEG internal
login="api"
password="dummy"
data='{"name": "steg.test77"}'
header_ct="Content-Type: application/json"

curl -v -u $login:$password --data-raw "$data" -H "$header_ct" $url

