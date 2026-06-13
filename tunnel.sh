#!/bin/bash
while true; do
  npx localtunnel --port 3001 --subdomain irs-joy-platform 2>&1 | tee /tmp/lt-irs.log
  echo "Tunnel died, restarting in 3 seconds..."
  sleep 3
done
