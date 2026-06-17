#!/bin/bash
# Start the Cloudflare tunnel for IRS Finance App
# Uses --config /dev/null to avoid system cloudflared config interference

while true; do
  echo "$(date) - Starting Cloudflare tunnel for port 3001..."
  HOME=/tmp/cf-irs-clean cloudflared tunnel --url http://localhost:3001 --no-autoupdate --config /dev/null 2>&1 | tee /tmp/cf-irs-tunnel.log
  echo "$(date) - Tunnel died, restarting in 5 seconds..."
  sleep 5
done
