# SaoML 8.0 Shell脚本
# By 凌一
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#######
Main()
{
Loading
}

Loading()
{
rm -rf $0 >/dev/null 2>&1
clear 
echo
echo "正在检查安装环境(预计三分钟内完成)...."
#安装环境 避免因缺失环境出现错误
yum -y install wget curl openssl net-tools net-tools.x86_64 >/dev/null 2>&1
Home_page
}

Home_page()
{
clear
echo
echo -e "\033[1;35m本脚本系统仅供学习使用，切勿用于商业用途\033[0m "
echo -e "\033[1;36m安装后请于24小时内自行删除\033[0m "
echo -e "\033[1;34m再次声明：本产品仅可用于国内网络环境的虚拟加密访问，用于数据保密。严禁用于任何违法违规用途。\033[0m "
echo -e "\033[1;33m严禁在非中国大陆地区机器上测试使用，发生一切后果需你自行承担，与本人无关，搭建即视为同意本声明。\033[0m "
echo 
echo -e "\033[1;36m回车开始搭建SaoML8.0系统！\033[0m "
read
sleep 1
echo -e "\033[1;32m正在载入信息.....\033[0m "
sleep 3
Get_IP
}

Get_IP()
{
clear
sleep 2
echo
echo "请选择IP源获取方式（自动获取失败的，请选择手动输入！）"
echo
echo "1、自动获取IP（默认获取方式，系统推荐！）"
echo "2、手动输入IP（仅在自动获取IP失败或异常时使用！）"
echo
read -p "请输入: " a
echo
k=$a
if [[ $k == 1 ]];then
sleep 1
echo "请稍等..."
sleep 1
IP=`curl -s ip.3322.net`;
wangka1=`ifconfig`;wangka2=`echo $wangka1|awk '{print $1}'`;wangka=${wangka2/:/};
clear
sleep 1
echo
echo -e "系统检测到的IP为：\033[34m"$IP"，网卡为："$wangka"\033[0m"
echo -e "如不正确请立即停止安装选择手动输入IP搭建，否则回车继续。"
read
sleep 1
echo "请稍等..."
sleep 1
Install_command
fi
if [[ $k == 2 ]];then
sleep 1
read -p "请输入您的IP/动态域名: " IP
if [ -z "$IP" ];then
IP=
fi
read -p "请输入您的网卡名称: " wangka
if [ -z "$wangka" ];then
wangka=
fi
echo "请稍等..."
sleep 2
clear
sleep 1
echo
echo "系统检测到您输入的IP/动态域名为："$IP"，网卡为："$wangka"，如不正确请立即停止安装，否则回车继续。"
read
sleep 1
echo "请稍等..."
sleep 1
Install_command
fi
echo -e "\033[31m输入错误！请重新运行脚本！\033[0m "
exit;0
}

Installation_options()
{
clear
echo
echo -e "\033[1;32m 搭建SaoML系统之前请先自定义以下信息，如不会填写请直接回车默认即可！ \033[0m \c"
echo
sleep 1
read -p "请设置MySQL密码(默认随机): " SqlPwd
if [ -z "$SqlPwd" ];then
SqlPwd=`date +%s%N | md5sum | head -c 20 ; echo`;
fi
echo -e "已设置MySQL密码为:\033[32m "$SqlPwd"\033[0m"
	
echo
read -p "请设置后台目录路径名称(默认随机): " Web
if [ -z "$Web" ];then
Web=`date +%s%N | md5sum | head -c 5 ; echo`;
fi
echo -e "已设置后台目录路径名称为:\033[32m "$Web"\033[0m"
	
echo
read -p "请设置APP名称(默认：笨逼加速器): " appmz
if [ -z "$appmz" ];then
appmz=笨逼加速器
fi
echo -e "已设置APP名称为:\033[32m "$appmz"\033[0m"
	
echo
read -p "请设置APP解析地址(可输入域名或IP，不带http://): " appip
if [ -z "$appip" ];then
appip=$IP
fi
echo -e "已设置APP解析地址为:\033[32m "$appip"\033[0m"
	
echo
read -p "请设置APP包名（默认：app.saomla.m）: " appbm
if [ -z "$appbm" ];then
appbm=app.saomla.m
fi
echo -e "已设置APP包名为:\033[32m "$appbm"\033[0m"
	
sleep 1
echo
echo "请稍等..."
sleep 2
echo
echo -e "\033[1;5;31m所有信息已收集完成！即将为您安装SaoML系统！\033[0m"
sleep 3
clear 
sleep 1
echo -e "\033[1;32m安装开始...\033[0m"
echo -e "\033[1;5;33m切记：只要不报错，就耐心等待！\033[0m"
sleep 5
}

replace_yum()
{
echo "正在更新YUM源，更新速度取决于服务器宽带......"
sleep 2
yum -y install iptables iptables-services > /dev/null 2>&1
mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo_bak > /dev/null 2>&1
curl -o /etc/yum.repos.d/CentOS-Base.repo -s http://oss.saoml.com/yum/public/Centos-7.repo > /dev/null 2>&1
rm -rf /etc/yum.repos.d/epel.repo > /dev/null 2>&1
rm -rf /etc/yum.repos.d/epel-testing.repo > /dev/null 2>&1
curl -o /etc/yum.repos.d/epel-testing.repo -s http://oss.saoml.com/yum/public/epel-testing.repo > /dev/null 2>&1
curl -o /etc/yum.repos.d/epel.repo -s http://oss.saoml.com/yum/public/epel.repo > /dev/null 2>&1
curl -o /etc/yum.repos.d/SaoML_PHP.repo -s http://oss.saoml.com/yum/public/SaoML_PHP.repo > /dev/null 2>&1
yum clean all > /dev/null 2>&1
yum makecache > /dev/null 2>&1
#防止搭建出错，更新系统
yum -y update > /dev/null 2>&1
yum -y install dmidecode java java-1.8.0-openjdk jre-1.8.0-openjdk libcurl libcurl-devel crontabs dos2unix ntp unzip zip gcc > /dev/null 2>&1
echo 'yum clean all' >> /bin/clean
rm -rf /bin/unzip > /dev/null 2>&1
curl -o /bin/unzip -s http://oss.saoml.com/yum/public/unzip > /dev/null 2>&1
chmod -R 777 /usr/bin > /dev/null 2>&1
}

Install_Dependency_file()
{
echo "为搭建系统做准备......"
rm -rf /var/saoml > /dev/null 2>&1
mkdir /var/saoml > /dev/null 2>&1
cd /var/saoml
wget -q http://oss.saoml.com/8/web-8.0.zip > /dev/null 2>&1
cd /var/saoml > /dev/null 2>&1
unzip -o -P Hc4620303+ web-8.0.zip > /dev/null 2>&1
}

Close_SELinux()
{
echo "正在关闭SELinux......"
setenforce 0 > /dev/null 2>&1
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config > /dev/null 2>&1
}

Install_Sysctl()
{
echo "正在配置IP转发......"
rm -rf /etc/sysctl.conf > /dev/null 2>&1
mv -f /var/saoml/etc/sysctl.conf /etc/sysctl.conf > /dev/null 2>&1
chmod 777 /etc/sysctl.conf > /dev/null 2>&1
sysctl -p /etc/sysctl.conf > /dev/null 2>&1
}

Install_firewall()
{
echo "正在配置IPtables防火墙......"
systemctl stop firewalld.service > /dev/null 2>&1
systemctl disable firewalld.service > /dev/null 2>&1
yum -y install iptables iptables-services > /dev/null 2>&1
systemctl stop iptables.service
systemctl start iptables.service > /dev/null 2>&1
iptables -F
service iptables save
systemctl restart iptables.service
iptables -A INPUT -s 127.0.0.1/32 -j ACCEPT
iptables -A INPUT -d 127.0.0.1/32 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 1024 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 137 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 138 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 440 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 1024 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 1194 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 1195 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 1196 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 1197 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 3389 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 8091 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 8128 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 53 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 67 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 68 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 69 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 123 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 137 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 138 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 161 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 636 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 1194 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 3389 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 6868 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 8060 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 5353 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 3848 -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A PREROUTING -p udp --dport 67 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 68 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 69 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 123 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 636 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 161 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 5353 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 6868 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 3389 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 138 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 137 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 1194 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 1195 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 1196 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 1197 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 8060 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING -p udp --dport 3848 -j REDIRECT --to-ports 53
iptables -t nat -A PREROUTING --dst 10.8.0.1 -p udp --dport 53 -j DNAT --to-destination 10.8.0.1:5353
iptables -t nat -A PREROUTING --dst 10.9.0.1 -p udp --dport 53 -j DNAT --to-destination 10.9.0.1:5353
iptables -t nat -A PREROUTING --dst 10.10.0.1 -p udp --dport 53 -j DNAT --to-destination 10.10.0.1:5353
iptables -t nat -A PREROUTING --dst 10.11.0.1 -p udp --dport 53 -j DNAT --to-destination 10.11.0.1:5353
iptables -t nat -A PREROUTING --dst 10.12.0.1 -p udp --dport 53 -j DNAT --to-destination 10.12.0.1:5353
iptables -P INPUT DROP
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $wangka -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o $wangka -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o $wangka -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.11.0.0/24 -o $wangka -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.12.0.0/24 -o $wangka -j MASQUERADE
iptables -t nat -A POSTROUTING -j MASQUERADE
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
service iptables save
systemctl restart iptables.service
}

Install_System_environment()
{
echo "正在配置安装流控系统......"
yum -y install httpd dnsmasq telnet lsof mariadb mariadb-server ipset openvpn > /dev/null 2>&1
yum -y install php70w php70w-fpm php70w-bcmath --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-cli --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-common php70w-dba php70w-devel --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-embedded --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-enchant php70w-gd php70w-imap --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-ldap --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-mbstring php70w-mcrypt php70w-mysqlnd --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-odbc --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-opcache php70w-pdo php70w-pdo_dblib --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-pear.noarch --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-pecl-apcu php70w-pecl-apcu-devel php70w-pecl-imagick --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-pecl-imagick-devel --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-pecl-mongodb php70w-pecl-redis php70w-pecl-xdebug --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-pgsql --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-xml php70w-xmlrpc php70w-intl --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-mcrypt --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php-fedora-autoloader php-php-gettext php-tcpdf --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php-tcpdf-dejavu-sans-fonts --nogpgcheck --skip-broken > /dev/null 2>&1
yum -y install php70w-tidy --nogpgcheck --skip-broken > /dev/null 2>&1
rpm -Uvh /var/saoml/openvpn.rpm --force --nodeps > /dev/null 2>&1
mv -f /var/saoml/etc/httpd.conf /etc/httpd/conf/httpd.conf > /dev/null 2>&1
cp -rf /var/saoml/etc/dnsmasq.conf /var/saoml/etc/ixed.7.0.lin /var/saoml/etc/my.cnf /var/saoml/etc/openvpn /var/saoml/etc/php.ini /var/saoml/etc/saoml_kernel_type /etc/ > /dev/null 2>&1
cp -rf /var/saoml/bin/hosts /var/saoml/bin/jk.sh /var/saoml/bin/neihe /var/saoml/bin/openvpn.bin /var/saoml/bin/rate.bin /var/saoml/bin/rate.sh /var/saoml/bin/sao /var/saoml/bin/saoml_auth /var/saoml/bin/saomlxs /var/saoml/bin/vpn /bin/ > /dev/null 2>&1
yum -y install mariadb mariadb-server > /dev/null 2>&1
systemctl start mariadb.service > /dev/null 2>&1
mysqladmin -u root password $SqlPwd > /dev/null 2>&1
mysql -u root -p$SqlPwd -e "create database vpndata" > /dev/null 2>&1
systemctl start httpd.service > /dev/null 2>&1
yum -y install php-fpm > /dev/null 2>&1
systemctl start php-fpm.service > /dev/null 2>&1
chmod -R 777 /bin/ > /dev/null 2>&1
chmod -R 777 /etc/openvpn/ > /dev/null 2>&1
sed -i "s/newpass/"$SqlPwd"/g" /etc/openvpn/auth_config.conf > /dev/null 2>&1
sed -i "s/服务器IP/"$IP"/g" /etc/openvpn/auth_config.conf > /dev/null 2>&1
chmod 777 /etc/dnsmasq.conf > /dev/null 2>&1
rm -rf /var/www/cgi-bin /var/www/html
cp -rf /var/saoml/html /var/www/ > /dev/null 2>&1

sed -i "s/服务器IP/"$IP"/g" /var/www/html/vpndata.sql > /dev/null 2>&1
mysql -uroot -p$SqlPwd vpndata < /var/www/html/vpndata.sql > /dev/null 2>&1
rm -rf /var/www/html/vpndata.sql > /dev/null 2>&1
sed -i "s/newpass/"$SqlPwd"/g" /var/www/html/config.php > /dev/null 2>&1
chmod -R 777 /var/www/ > /dev/null 2>&1
mv /var/www/html/admin /var/www/html/$Web > /dev/null 2>&1
mkdir /etc/rate.d/
chmod -R 0777 /etc/rate.d/ > /dev/null 2>&1
cp -rf /var/saoml/res /root/ > /dev/null 2>&1
chmod -R 777 /root
mv /root/res/saoml.service /lib/systemd/system/saoml.service
chmod -R 777 /lib/systemd/system/saoml.service
}

Install_App()
{
echo "正在制作APP....."
/var/www/html/shell/appgf "$IP" "1024" "$appmz" "$appbm" "app.saomlb.m" > /dev/null 2>&1
}
Install_Startup_program()
{
echo "正在处理依赖......"
echo '1' > /usr/lib/libgcc_libeses.0.so.1
echo '#SaoML官网：ml.saoml.com' > /etc/saoml_hosts
echo '###############################请勿删除上方代码###############################' >> /etc/hosts
chmod 777 /etc/saoml_hosts > /dev/null 2>&1
chmod 777 /etc/hosts > /dev/null 2>&1
systemctl restart crond.service > /dev/null 2>&1
mv -f /etc/ixed.7.0.lin /usr/lib64/php/modules/ixed.7.0.lin > /dev/null 2>&1
chmod 777 /usr/lib64/php/modules/ixed.7.0.lin > /dev/null 2>&1
systemctl restart openvpn@server1194.service > /dev/null 2>&1
systemctl restart php-fpm.service > /dev/null 2>&1
systemctl restart httpd.service > /dev/null 2>&1
systemctl restart iptables.service > /dev/null 2>&1
systemctl restart mariadb.service > /dev/null 2>&1
systemctl restart dnsmasq.service > /dev/null 2>&1
chmod 777 /bin/sao > /dev/null 2>&1
sao install > /dev/null 2>&1
}

Install_Crond()
{
echo "正在配置自动任务......"
echo '*/5 * * * * sao start #每5分钟检查一次守护进程' > /etc/saoml_crontab
echo '0 2 * * * saomlxs #每天凌晨2点自动校时' >> /etc/saoml_crontab
echo '0 2 * * * rm -rf /var/log/httpd/access_log /var/log/httpd/error_log #每天凌晨2点清空网站日志' >> /etc/saoml_crontab
echo '0 1 * * * rm -rf /var/www/*.log #每天凌1点清空监控日志' >> /etc/saoml_crontab
echo '0 0 1 * * vpn top #每月重置一次排行榜' >> /etc/saoml_crontab
crontab /etc/saoml_crontab > /dev/null 2>&1
chmod 777 /etc/saoml_crontab > /dev/null 2>&1
systemctl enable mariadb.service > /dev/null 2>&1
systemctl enable httpd.service > /dev/null 2>&1
systemctl enable php-fpm.service > /dev/null 2>&1
systemctl enable openvpn@server1194.service > /dev/null 2>&1
systemctl enable openvpn@server1195.service > /dev/null 2>&1
systemctl enable openvpn@server1196.service > /dev/null 2>&1
systemctl enable openvpn@server1197.service > /dev/null 2>&1
systemctl enable openvpn@server-udp.service > /dev/null 2>&1
systemctl enable dnsmasq.service > /dev/null 2>&1
systemctl enable crond.service > /dev/null 2>&1
systemctl enable iptables.service > /dev/null 2>&1
systemctl enable saoml.service > /dev/null 2>&1
}

Install_Last()
{
echo "正在执行最后操作......"
unsql > /dev/null 2>&1
rm -rf /var/saoml > /dev/null 2>&1
systemctl restart dnsmasq.service
systemctl restart crond.service
systemctl restart iptables.service
systemctl restart saoml.service > /dev/null 2>&1
systemctl restart mariadb.service > /dev/null 2>&1
systemctl restart httpd.service > /dev/null 2>&1
systemctl restart php-fpm.service
systemctl restart openvpn@server1194.service
systemctl restart openvpn@server1195.service
systemctl restart openvpn@server1196.service
systemctl restart openvpn@server1197.service
systemctl restart openvpn@server-udp.service
saomlxs
}

Installation_is_complete()
{
clear
echo "----------------------------------------"
echo -e "\033[1;32m 搭建完成，后台地址账号密码等信息请输入以下命令查看 cat /home/messages.txt \033[0m "
echo -e "\033[1;33m 为了安全起见，强烈建议搭建后保存此文件到本地并删除服务器内此文件并修改默认账号密码\033[0m "
echo -e "\033[1;34m 执行rm -rf /home/messages.txt 命令即可删除本文件\033[0m "
echo "
---------------------------------------------------------
恭喜各位基友,您已经成功安装SaoML流控流量控制系统
---------------------------------------------------------
管理员后台: http://"$IP":1024/"$Web"
管理员账号: admin
管理员密码: admin
---------------------------------------------------------
数据库地址: http://"$IP":1024/"$Web"/phpmyadmin
数据库账号: root
数据库密码: "$SqlPwd"
---------------------------------------------------------
代理控制台: http://"$IP":1024/daili
用户控制台: http://"$IP":1024
---------------------------------------------------------
默认APP下载地址: http://"$IP":1024/saoml.apk
PC软件下载地址: https://csao.lanzoui.com/b03gcoqre
IOS软件: 使用国际ID 搜索openvpn或opentunnel即可
---------------------------------------------------------
更多操作可执行：vpn  命令查看
---------------------------------------------------------
守护模块查看命令：sao 
---------------------------------------------------------
使用文档请查看：http://www.saoml.com/index.php/category/ml/ 
---------------------------------------------------------
如果安装完毕以后无法访问后台请进服务器控制台开安全组有些叫防火墙一个意思，端口全开
---------------------------------------------------------" >> /home/messages.txt
cat /home/messages.txt
exit 0;
}

Install_command()
{
	#变量安装命令
	Installation_options
	replace_yum
	Install_Dependency_file
	Close_SELinux
	Install_Sysctl
	Install_firewall
	Install_System_environment
	Install_App
	Install_Startup_program
	Install_Crond
	Install_Last
	Installation_is_complete
}

Main
exit;0
