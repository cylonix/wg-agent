#! /bin/bash

echo "Updating code on wg-server..."
vagrant rsync wg-server
vagrant ssh wg-server -c "sudo systemctl stop wg-agent"
echo "Rebuild and update wg-agent on wg-server..."
vagrant ssh wg-server -c "cd /wg-agent/wg-mgr-rs && cargo build"
vagrant ssh wg-server -c "sudo cp /wg-agent/wg-mgr-rs/target/debug/main /usr/bin/wg-agent"
vagrant ssh wg-server -c "sudo systemctl start wg-agent"
vagrant ssh wg-server -c "sudo systemctl status -n0 wg-agent"
echo "wg-agent updated and service restarted on wg-server"