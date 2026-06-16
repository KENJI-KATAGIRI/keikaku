#!/bin/bash
# keikaku-manager セットアップスクリプト（sudo必要）
set -e

# systemdサービスインストール
sudo cp /tmp/keikaku-manager.service /etc/systemd/system/keikaku-manager.service
sudo systemctl daemon-reload
sudo systemctl enable keikaku-manager
sudo systemctl start keikaku-manager

# nginx設定更新
sudo cp /tmp/gaiaarts_new.conf /etc/nginx/sites-enabled/gaiaarts.org
sudo nginx -t && sudo systemctl reload nginx

echo "セットアップ完了！"
echo "動作確認: curl -s http://localhost:8312/ | head -5"
