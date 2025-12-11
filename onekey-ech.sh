#!/bin/bash
# onekey ech
linux_os=("Debian" "Ubuntu" "CentOS" "Fedora" "Alpine")
linux_update=("apt update" "apt update" "yum -y update" "yum -y update" "apk update")
linux_install=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "apk add -f")
n=0
for i in `echo ${linux_os[@]}`
do
	if [ $i == $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') ]
	then
		break
	else
		n=$[$n+1]
	fi
done
if [ $n == 5 ]
then
	echo 当前系统$(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2)没有适配
	echo 默认使用APT包管理器
	n=0
fi
if [ -z $(type -P screen) ]
then
	${linux_update[$n]}
	${linux_install[$n]} screen
fi
if [ -z $(type -P curl) ]
then
	${linux_update[$n]}
	${linux_install[$n]} curl
fi

function quicktunnel(){
case "$(uname -m)" in
	x86_64 | x64 | amd64 )
	if [ ! -f "ech-server-linux" ]
	then
	curl -L https://github.com/hhsw2015/ech-workers/blob/main/ech-server-linux-amd64 -o ech-server-linux
	fi
	if [ ! -f "opera-linux" ]
	then
	curl -L https://github.com/Snawoot/opera-proxy/releases/latest/download/opera-proxy.linux-amd64 -o opera-linux
	fi
	if [ ! -f "cloudflared-linux" ]
	then
	curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared-linux
	fi
	;;
	i386 | i686 )
	if [ ! -f "ech-server-linux" ]
	then
	curl -L https://github.com/hhsw2015/ech-workers/blob/main/ech-server-linux-386 -o ech-server-linux
	fi
	if [ ! -f "opera-linux" ]
	then
	curl -L https://github.com/Snawoot/opera-proxy/releases/latest/download/opera-proxy.linux-386 -o opera-linux
	fi
	if [ ! -f "cloudflared-linux" ]
	then
	curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386 -o cloudflared-linux
	fi
	;;
	armv8 | arm64 | aarch64 )
	if [ ! -f "ech-server-linux" ]
	then
	curl -L https://github.com/hhsw2015/ech-workers/blob/main/ech-server-linux-arm64 -o ech-server-linux
	fi
	if [ ! -f "opera-linux" ]
	then
	curl -L https://github.com/Snawoot/opera-proxy/releases/latest/download/opera-proxy.linux-arm64 -o opera-linux
	fi
	if [ ! -f "cloudflared-linux" ]
	then
	curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 -o cloudflared-linux
	fi
	;;
	* )
	echo 当前架构$(uname -m)没有适配
	exit
	;;
esac
chmod +x cloudflared-linux ech-server-linux opera-linux
if [ "$opera" = "1" ]
then
	operaport=$(get_free_port)
	screen -dmUS opera ./opera-linux -country $country -socks-mode -bind-address "127.0.0.1:$operaport"
fi
sleep 1
wsport=$(get_free_port)
if [ -z "$token" ]
then
	if [ "$opera" = "1" ]
	then
		screen -dmUS ech ./ech-server-linux -l ws://127.0.0.1:$wsport -f socks5://127.0.0.1:$operaport
	else
		screen -dmUS ech ./ech-server-linux -l ws://127.0.0.1:$wsport
	fi
else
	if [ "$opera" = "1" ]
	then
		screen -dmUS ech ./ech-server-linux -l ws://127.0.0.1:$wsport -token $token -f socks5://127.0.0.1:$operaport
	else
		screen -dmUS ech ./ech-server-linux -l ws://127.0.0.1:$wsport -token $token
	fi
fi
metricsport=$(get_free_port)
./cloudflared-linux update
screen -dmUS argo ./cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel --url 127.0.0.1:$wsport --metrics 0.0.0.0:$metricsport
while true; do
    echo "正在尝试获取内容..."
    RESP=$(curl -s "http://127.0.0.1:$metricsport/metrics")

    # 若curl成功且包含userHostname则处理
    if echo "$RESP" | grep -q 'userHostname='; then
        echo "获取成功，正在解析..."

        # 从返回内容中提取域名
        DOMAIN=$(echo "$RESP" | grep 'userHostname="' | sed -E 's/.*userHostname="https?:\/\/([^"]+)".*/\1/')

        echo "提取到的域名：$DOMAIN"
        break
    else
        echo "未获取到userHostname，1秒后重试..."
        sleep 1
    fi
done
clear
if [ -z "$token" ]
then
	echo 未设置token,链接为: $DOMAIN:443
else
	echo 已设置token,链接为: $DOMAIN:443 身份令牌: $token
fi
echo 可以访问 http://$(curl -4 -s https://www.cloudflare.com/cdn-cgi/trace | grep ip= | cut -d= -f2):$metricsport/metrics 查找 userHostname
}

get_free_port() {
    while true; do
        PORT=$((RANDOM + 1024))  # 避免系统保留端口
        if ! lsof -i TCP:$PORT >/dev/null 2>&1; then
            echo $PORT
            return
        fi
    done
}

clear
echo 梭哈模式不需要自己提供域名,使用CF ARGO QUICK TUNNEL创建快速链接
echo 梭哈模式在重启或者脚本再次运行后失效,如果需要使用需要再次运行创建

echo -e '\n'梭哈是一种智慧!!!梭哈!梭哈!梭哈!梭哈!梭哈!梭哈!梭哈...'\n'
echo 1.梭哈模式
echo 2.停止服务
echo 3.清空缓存
echo -e 0.退出脚本'\n'
read -p "请选择模式(默认1):" mode
if [ -z "$mode" ]
then
	mode=1
fi
if [ $mode == 1 ]
then
	read -p "是否启用opera前置代理(0.不启用[默认],1.启用):" opera
	if [ -z "$opera" ]
	then
		opera=0
	fi
	if [ "$opera" = "1" ]
	then
		echo 注意:opera前置代理仅支持AM,AS,EU地区
		echo AM: 北美地区
		echo AS: 亚太地区
		echo EU: 欧洲地区
		read -p "请输入opera前置代理的国家代码(默认AM):" country
		if [ -z "$country" ]
		then
			country=AM
		fi
		country=${country^^}
		if [ "$country" != "AM" ] && [ "$country" != "AS" ] && [ "$country" != "EU" ]
		then
			echo 请输入正确的opera前置代理国家代码
			exit
		fi
	fi
	if [ "$opera" != "0" ] && [ "$opera" != "1" ]
	then
		echo 请输入正确的opera前置代理模式
		exit
	fi
	read -p "请选择cloudflared连接模式IPV4或者IPV6(输入4或6,默认4):" ips	
	if [ -z "$ips" ]
	then
		ips=4
	fi
	if [ "$ips" != "4" ] && [ "$ips" != "6" ]
	then
		echo 请输入正确的cloudflared连接模式
		exit
	fi
	read -p "请设置ech-tunnel的token(可留空):" token
	screen -wipe
	screen -S ech -X quit
	while true
	do
	if [ $(screen -S ech -X quit | grep No | grep -v grep | wc -l) -eq 1 ]
	then
		break
	else
		echo 等待ech-tunnel退出...
		sleep 1
	fi
	done
	screen -S opera -X quit
	while true
	do
	if [ $(screen -S opera -X quit | grep No | grep -v grep | wc -l) -eq 1 ]
	then
		break
	else
		echo 等待opera退出...
		sleep 1
	fi
	done
	while true
	do
	if [ $(screen -S argo -X quit | grep No | grep -v grep | wc -l) -eq 1 ]
	then
		break
	else
		echo 等待argo退出...
		sleep 1
	fi
	done
	clear
	sleep 1
	quicktunnel
elif [ $mode == 2 ]
then
	screen -wipe
	screen -S ech -X quit
	while true
	do
	if [ $(screen -S ech -X quit | grep No | grep -v grep | wc -l) -eq 1 ]
	then
		break
	else
		echo 等待ech-tunnel退出...
		sleep 1
	fi
	done
	screen -S opera -X quit
	while true
	do
	if [ $(screen -S opera -X quit | grep No | grep -v grep | wc -l) -eq 1 ]
	then
		break
	else
		echo 等待opera退出...
		sleep 1
	fi
	done
	while true
	do
	if [ $(screen -S argo -X quit | grep No | grep -v grep | wc -l) -eq 1 ]
	then
		break
	else
		echo 等待argo退出...
		sleep 1
	fi
	done
	clear
elif [ $mode == 3 ]
then
	screen -wipe
	screen -S ech -X quit
	while true
	do
	if [ $(screen -S ech -X quit | grep No | grep -v grep | wc -l) -eq 1 ]
	then
		break
	else
		echo 等待ech-tunnel退出...
		sleep 1
	fi
	done
	screen -S opera -X quit
	while true
	do
	if [ $(screen -S opera -X quit | grep No | grep -v grep | wc -l) -eq 1 ]
	then
		break
	else
		echo 等待opera退出...
		sleep 1
	fi
	done
	while true
	do
	if [ $(screen -S argo -X quit | grep No | grep -v grep | wc -l) -eq 1 ]
	then
		break
	else
		echo 等待argo退出...
		sleep 1
	fi
	done
	clear
	rm -rf cloudflared-linux ech-server-linux opera-linux
else
	echo 退出成功
	exit
fi
