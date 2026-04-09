#!/bin/bash
set -e

echo "═══════════════════════════════════════"
echo "  墨韵 · InkWell 一键部署脚本"
echo "═══════════════════════════════════════"

# Update system
echo ">>> 更新系统..."
apt update && apt upgrade -y

# Install Node.js 20
echo ">>> 安装 Node.js 20..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# Install build tools (for better-sqlite3)
echo ">>> 安装编译工具..."
apt install -y build-essential python3 python3-pip

# Install edge-tts
echo ">>> 安装 edge-tts..."
pip3 install edge-tts --break-system-packages 2>/dev/null || pip3 install edge-tts

# Install PM2
echo ">>> 安装 PM2..."
npm install -g pm2

# Install Nginx
echo ">>> 安装 Nginx..."
apt install -y nginx

# Install Certbot (for HTTPS)
echo ">>> 安装 Certbot..."
apt install -y certbot python3-certbot-nginx

# Setup application directory
APP_DIR="/opt/inkwell"
echo ">>> 设置应用目录: $APP_DIR"

if [ ! -d "$APP_DIR" ]; then
  echo ">>> 克隆仓库（请替换为你的仓库地址）..."
  echo "    git clone https://github.com/YOUR_USERNAME/inkwell.git $APP_DIR"
  mkdir -p $APP_DIR
fi

cd $APP_DIR

# Install dependencies
echo ">>> 安装 Node.js 依赖..."
npm install --production

# Generate JWT secret
JWT_SECRET=$(openssl rand -hex 32)
echo ">>> 生成 JWT 密钥: $JWT_SECRET"

# Create environment file
cat > .env << EOF
NODE_ENV=production
PORT=3000
JWT_SECRET=$JWT_SECRET
MAX_USERS=2
EOF

# Setup PM2
echo ">>> 配置 PM2..."
JWT_SECRET=$JWT_SECRET pm2 start ecosystem.config.js
pm2 save
pm2 startup

# Configure Nginx
echo ">>> 配置 Nginx..."
read -p "请输入你的域名 (例如 inkwell.example.com): " DOMAIN

cat > /etc/nginx/sites-available/inkwell << EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;

        # Upload size limit
        client_max_body_size 100M;
    }
}
EOF

ln -sf /etc/nginx/sites-available/inkwell /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# SSL Certificate
echo ">>> 获取 SSL 证书..."
certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN || {
  echo "⚠ SSL 证书获取失败，请稍后手动运行: certbot --nginx -d $DOMAIN"
}

# Setup firewall
echo ">>> 配置防火墙..."
ufw allow 22
ufw allow 80
ufw allow 443
ufw --force enable

# Create swap (for 1GB RAM VPS)
echo ">>> 创建交换空间..."
if [ ! -f /swapfile ]; then
  fallocate -l 1G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo ""
echo "═══════════════════════════════════════"
echo "  ✓ 部署完成！"
echo "  ✓ 应用地址: https://$DOMAIN"
echo "  ✓ PM2 状态: pm2 status"
echo "  ✓ 查看日志: pm2 logs inkwell"
echo "═══════════════════════════════════════"
