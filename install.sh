#!/usr/bin/env bash


. ./garudrecon.cfg


if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi


declare -A gotools
gotools["Amass"]="go install -v github.com/OWASP/Amass/v3/...@master"
gotools["anew"]="go install -v github.com/tomnomnom/anew@latest"
gotools["assetfinder"]="go install github.com/tomnomnom/assetfinder@latest"
gotools["airixss"]="go install github.com/ferreiraklet/airixss@latest"
gotools["burl"]="go install github.com/tomnomnom/burl@latest"
gotools["crlfuzz"]="GO111MODULE=on go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
gotools["cent"]="GO111MODULE=on go install github.com/xm1k3/cent@latest"
gotools["crobat"]="go install github.com/cgboal/sonarsearch/cmd/crobat@latest"
gotools["cf-check"]="go install github.com/dwisiswant0/cf-check@latest"
gotools["chaos-client"]="go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
gotools["concurl"]="go install github.com/tomnomnom/concurl@latest"
gotools["dnsx"]="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
gotools["dalfox"]="go install github.com/hahwul/dalfox/v2@latest"
gotools["dirdar"]="go install github.com/m4dm0e/dirdar@latest"
gotools["roboxtractor"]="go install github.com/Josue87/roboxtractor@latest"
gotools["ffuf"]="go install github.com/ffuf/ffuf@latest"
gotools["fff"]="go install github.com/tomnomnom/fff@latest"
gotools["GoLinkFinder"]="go install github.com/0xsha/GoLinkFinder@latest"
gotools["gobuster"]="go install github.com/OJ/gobuster/v3@latest"
gotools["gospider"]="GO111MODULE=on go install github.com/jaeles-project/gospider@latest"
gotools["gau"]="go install github.com/lc/gau/v2/cmd/gau@latest"
gotools["gauplus"]="go install github.com/bp0lr/gauplus@latest"
gotools["getJS"]="go install github.com/003random/getJS@latest"
gotools["github-endpoints"]="go install github.com/gwen001/github-endpoints@latest"
gotools["github-subdomains"]="go install github.com/gwen001/github-subdomains@latest"
gotools["gowitness"]="go install github.com/sensepost/gowitness@latest"
gotools["gron"]="go install github.com/tomnomnom/gron@latest"
gotools["Gxss"]="go install github.com/KathanP19/Gxss@latest"
gotools["gotator"]="go install github.com/Josue87/gotator@latest"
gotools["httprobe"]="go install github.com/tomnomnom/httprobe@latest"
gotools["headi"]="go install github.com/mlcsec/headi@latest"
gotools["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
gotools["hakrawler"]="go install github.com/hakluke/hakrawler@latest"
gotools["interactsh-client"]="go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
gotools["Jeeves"]="go install github.com/ferreiraklet/Jeeves@latest"
gotools["jaeles"]="GO111MODULE=on go install github.com/jaeles-project/jaeles@latest"
gotools["kxss"]="go install github.com/Emoe/kxss@latest"
gotools["meg"]="go install github.com/tomnomnom/meg@latest"
gotools["naabu"]="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
gotools["notify"]="go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
gotools["osmedeus"]="go install -v github.com/j3ssie/osmedeus@latest"
gotools["puredns"]="go install github.com/d3mondev/puredns/v2@latest"
gotools["qsreplace"]="go install github.com/tomnomnom/qsreplace@latest"
gotools["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
gotools["soxy"]="go install github.com/pry0cc/soxy@latest"
gotools["subjs"]="GO111MODULE=on go install -v github.com/lc/subjs@latest"
gotools["SubOver"]="go install github.com/Ice3man543/SubOver@latest"
gotools["shuffledns"]="go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
gotools["subjack"]="go install github.com/haccer/subjack@latest"
gotools["subzy"]="go install -v github.com/lukasikic/subzy@latest"
gotools["tko-subs"]="go install github.com/anshumanbh/tko-subs@latest"
gotools["unfurl"]="go install github.com/tomnomnom/unfurl@latest"
gotools["waybackurls"]="go install github.com/tomnomnom/waybackurls@latest"
gotools["wordlistgen"]="go install github.com/ameenmaali/wordlistgen@latest"


declare -A repos
repos["AnalyticsRelationships"]="Josue87/AnalyticsRelationships"
repos["asnlookup"]="yassineaboukir/asnlookup"
repos["Blazy"]="s0md3v/Blazy"
repos["bfac"]="mazen160/bfac"
repos["bucket-stream"]="eth0izzle/bucket-stream"
repos["crtndstry"]="nahamsec/crtndstry"
repos["cred_scanner"]="disruptops/cred_scanner"
repos["cloud_enum"]="initstring/cloud_enum"
repos["crawler"]="ghostlulzhacks/crawler"
repos["commix"]="commixproject/commix"
repos["CMSmap"]="Dionach/CMSmap"
repos["CMSeeK"]="Tuhinshubhra/CMSeeK"
repos["Corsy"]="s0md3v/Corsy"
repos["CORStest"]="RUB-NDS/CORStest"
repos["CeWL"]="digininja/CeWL"
repos["ctfr"]="UnaPibaGeek/ctfr"
repos["CloudFail"]="m0rtem/CloudFail"
repos["degoogle_hunter"]="six2dez/degoogle_hunter"
repos["drupwn"]="immunIT/drupwn"
repos["datasploit"]="DataSploit/datasploit"
repos["dirsearch"]="maurosoria/dirsearch"
repos["domain_analyzer"]="eldraco/domain_analyzer"
repos["DumpsterDiver"]="securing/DumpsterDiver"
repos["dnscan"]="rbsec/dnscan"
repos["dnsrecon"]="darkoperator/dnsrecon"
repos["dnsvalidator"]="vortexau/dnsvalidator"
repos["EyeWitness"]="FortyNorthSecurity/EyeWitness"
repos["GitTools"]="internetwache/GitTools"
repos["git-secrets"]="awslabs/git-secrets"
repos["GCPBucketBrute"]="RhinoSecurityLabs/GCPBucketBrute"
repos["GitDorker"]="obheda12/GitDorker"
repos["JSParser"]="nahamsec/JSParser"
repos["joomscan"]="rezasp/joomscan"
repos["JSA"]="w9w/JSA"
repos["jsearch"]="incogbyte/jsearch"
repos["knock"]="guelfoweb/knock"
repos["lazys3"]="nahamsec/lazys3"
repos["lazyrecon"]="nahamsec/lazyrecon"
repos["LinkFinder"]="GerbenJavado/LinkFinder"
repos["massdns"]="blechschmidt/massdns"
repos["masscan"]="robertdavidgraham/masscan"
repos["OpenRedireX"]="devanshbatham/OpenRedireX"
repos["ParamSpider"]="devanshbatham/ParamSpider"
repos["resolveDomains"]="Josue87/resolveDomains"
repos["sqliv"]="the-robot/sqliv"
repos["sqlmate"]="s0md3v/sqlmate"
repos["Sublist3r"]="aboul3la/Sublist3r"
repos["Source2URL"]="danielmiessler/Source2URL"
repos["SubDomainizer"]="nsonaniya2010/SubDomainizer"
repos["subbrute"]="TheRook/subbrute"
repos["sub.sh"]="cihanmehmet/sub.sh"
repos["s3brute"]="ghostlulzhacks/s3brute"
repos["shcheck"]="santoru/shcheck"
repos["Sn1per"]="1N3/Sn1per"
repos["subdomain-takeover"]="antichown/subdomain-takeover"
repos["spaces-finder"]="appsecco/spaces-finder"
repos["SecretFinder"]="m4ll0k/SecretFinder"
repos["takeover"]="m4ll0k/takeover"
repos["teh_s3_bucketeers"]="tomdev/teh_s3_bucketeers"
repos["urldedupe"]="ameenmaali/urldedupe"
repos["uDork"]="m3n0sd0n4ld/uDork"
repos["virtual-host-discovery"]="jobertabma/virtual-host-discovery"
repos["waybackMachine"]="ghostlulzhacks/waybackMachine"
repos["wafw00f"]="EnableSecurity/wafw00f"
repos["XXEinjector"]="enjoiz/XXEinjector"
repos["xnLinkFinder"]="xnl-h4ck3r/xnLinkFinder"
repos["XSStrike"]="s0md3v/XSStrike"


declare -A wordlists
wordlists["content_discovery_all.txt"]="wget -q -O - https://gist.githubusercontent.com/jhaddix/b80ea67d85c13206125806f0828f4d10/raw/c81a34fe84731430741e0463eb6076129c20c4c0/content_discovery_all.txt > ${tools_dir}/content_discovery_all.txt"
wordlists["all.txt"]="wget -q -O - https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt > ${tools_dir}/all.txt"
wordlists["leaky-paths.txt"]="wget -q -O - https://raw.githubusercontent.com/ayoubfathi/leaky-paths/main/leaky-paths.txt > ${tools_dir}/leaky-paths.txt"
wordlists["permutations_list.txt"]="wget -q -O - https://gist.github.com/six2dez/ffc2b14d283e8f8eff6ac83e20a3c4b4/raw > ${permutations}"
wordlists["onelistforallmicro.txt"]="wget -q -O - https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt > ${onelistforallmicro}"
wordlists["fuzz.txt"]="wget -q -O - https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt > ${fuzz_wordlist}"
wordlists["best-dns-wordlist.txt"]="wget -q -O - https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt > ${subs_wordlist_big}"
wordlists["resolvers-trusted.txt"]="wget -q -O - https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt > ${resolvers_trusted}"
wordlists["resolvers.txt"]="wget -q -O - https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt > ${resolvers}"
wordlists["subdomains.txt"]="wget -q -O - https://gist.github.com/six2dez/a307a04a222fab5a57466c51e1569acf/raw > ${subs_wordlist}"
wordlists["lfi_wordlist.txt"]="wget -q -O - https://gist.githubusercontent.com/six2dez/a89a0c7861d49bb61a09822d272d5395/raw > ${lfi_wordlist}"
wordlists["ssti_wordlist.txt"]="wget -q -O - https://gist.githubusercontent.com/six2dez/ab5277b11da7369bf4e9db72b49ad3c1/raw > ${ssti_wordlist}"
wordlists["headers_inject.txt"]="wget -q -O - https://gist.github.com/six2dez/d62ab8f8ffd28e1c206d401081d977ae/raw > ${headers_wordlist}"
wordlists["nmap-bootstrap.xsl"]="wget -q -O - https://github.com/honze-net/nmap-bootstrap-xsl/raw/master/nmap-bootstrap.xsl > ${headers_wordlist}/nmap-bootstrap.xsl"


declare -A others
others["awscli"]="pip install awscli --upgrade --user"
others["arjun"]="pip3 install arjun"
others["aiodnsbrute"]="pip install aiodnsbrute"
others["aquatone"]="wget -P ~/tools_dir -N https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip && unzip -o ~/tools/aquatone_linux_amd64_1.7.0.zip && mv -f aquatone /usr/bin/"
others["altdns"]="pip3 install py-altdns==1.0.2"
others["bhedak"]="pip3 install bhedak"
others["broken-link-checker"]="sudo npm install broken-link-checker -g"
others["corscanner"]="pip install corscanner"
others["CrackMapExec"]="wget -O ~/tools_dir/CrackMapExec-5.2.2.zip -N https://github.com/byt3bl33d3r/CrackMapExec/archive/refs/tags/v5.2.2.zip && unzip -o CrackMapExec-5.2.2.zip && cd CrackMapExec-5.2.2 && python3 -m pip install -r requirements.txt"
others["droopescan"]="pip install droopescan"
others["domain-finder"]="wget -P ~/tools_dir -N https://raw.githubusercontent.com/gwen001/pentest-tools/master/domain-finder.py "
others["dnsenum"]="sudo apt-get install -y dnsenum"
others["dnsgen"]="pip3 install dnsgen"
others["feroxbuster"]="wget -P ~/tools_dir -N https://github.com/epi052/feroxbuster/releases/download/2.7.1/x86_64-linux-feroxbuster.zip && unzip -o ~/tools/x86_64-linux-feroxbuster.zip && chmod +x feroxbuster && sudo mv -f feroxbuster /usr/bin/"
others["fdns"]="wget -P ~/tools_dir -N https://opendata.rapid7.com/sonar.fdns_v2/2022-08-05-1659658263-fdns_a.json.gz"
others["git-dumper"]="pip install git-dumper"
others["grepcidr"]="apt install grepcidr"
# others["gofingerprint"]="git clone https://github.com/Static-Flow/gofingerprint.git ~/tools_dir/gofingerprint && cd gofingerprint/cmd/gofingerprint && go build gofingerprint.go"
others["gitrob"]="wget -P ~/tools -N https://github.com/michenriksen/gitrob/releases/download/v2.0.0-beta/gitrob_linux_amd64_2.0.0-beta.zip && unzip -o ~/tools/gitrob_linux_amd64_2.0.0-beta.zip && sudo mv -f gitrob /usr/bin/"
others["github-subdomains"]="wget -P ~/tools_dir -N https://raw.githubusercontent.com/gwen001/github-search/master/github-subdomains.py"
others["gf_patterns"]="go install github.com/tomnomnom/gf@latest && cp ~/go/bin/gf /usr/bin/ && mkdir ~/.gf && git clone https://github.com/Sherlock297/gf_patterns.git && cd gf_patterns && cp *.json ~/.gf"
others["nmap"]="sudo apt-get install -y nmap"
others["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && sudo cp /root/go/bin/nuclei /usr/local/go/bin/ && nuclei -update-templates"
others["parallel"]="sudo apt install -y parallel"
others["rustscan"]="wget -P ~/tools_dir -N https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb && sudo dpkg -i ~/tools/rustscan_2.0.1_amd64.deb"
others["sqlmap"]="git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ~/tools_dir/sqlmap-dev"
others["Sudomy"]="git clone --recursive https://github.com/screetsec/Sudomy.git ~/tools_dir/Sudomy && cd Sudomy && python3 -m pip install -r requirements.txt"
others["s3scanner"]="pip3 install s3scanner"
others["trufflehog"]="git clone https://github.com/trufflesecurity/trufflehog.git ~/tools_dir/trufflehog && cd trufflehog; go install"
others["testssl"]="git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/tools_dir/testssl.sh "
others["uro"]="pip3 install uro"
others["waybackrobots"]="wget -P ~/tools_dir -N https://gist.githubusercontent.com/mhmdiaa/2742c5e147d49a804b408bfed3d32d07/raw/5dd007667a5b5400521761df931098220c387551/waybackrobots.py"
others["wpscan"]="sudo gem install wpscan"
others["xsrfprobe"]="pip install xsrfprobe"
others["XSpear"]="gem install colorize && gem install selenium-webdriver && gem install terminal-table && gem install progress_bar && gem install XSpear"



install_apt(){
    eval sudo apt update -y $debug_std
    eval sudo apt upgrade $debug_std
    eval sudo apt install chromium-browser -y $debug_std
    eval sudo apt install chromium -y $debug_std
    eval sudo apt install npm -y $debug_std
    eval sudo apt install python3 python3-pip python3-shodan build-essential gcc cmake ruby whois git curl libpcap-dev wget zip python3-dev pv dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq apt-transport-https lynx tor medusa xvfb libxml2-utils procps bsdmainutils libdata-hexdump-perl aptitude -y $debug_std
    eval sudo aptitude install jq pigz
}


# install_pacman(){
#     eval sudo pacman -Sy install python python-pip base-devel gcc cmake ruby git curl libpcap whois wget zip pv bind openssl libffi libxml2 libxslt zlib nmap jq lynx tor medusa xorg-server-xvfb -y $debug_std
#     eval sudo systemctl enable --now tor.service $debug_std
#     rust=$(curl https://sh.rustup.rs -sSf | sh -s -- -y) $debug_std
#     eval source $HOME/.cargo/env $debug_std
#     eval cargo install ripgen $debug_std
# }


# install_yum(){
#     eval sudo yum groupinstall "Development Tools" -y $debug_std
#     eval sudo yum install python3 python3-pip gcc cmake ruby git curl libpcap-dev wget whois zip python3-devel pv bind-utils libopenssl-devel libffi-devel libxml2-devel libxslt-devel zlib-devel nmap jq lynx tor medusa xorg-x11-server-xvfb -y $debug_std
#     rust=$(curl https://sh.rustup.rs -sSf | sh -s -- -y) $debug_std
#     eval source $HOME/.cargo/env $debug_std
#     eval cargo install ripgen $debug_std
# }


eval git config --global --unset http.proxy
eval git config --global --unset https.proxy



printf "${bblue}Installing system packages ${reset}\n\n"
if [ -f /etc/os-release ]; then install_apt;
elif [ -f /etc/redhat-release ]; then install_yum;
elif [ -f /etc/arch-release ]; then install_pacman;
fi



echo -e "Checking Golang latest version"
go_online_version=$(curl -L -s https://golang.org/VERSION?m=text -w "\n")
go_system_version=$(go version | awk {'print $3'})


if [[ "$go_online_version" == "$go_system_version" ]]; then
    echo -e "Golang is already installed and updated"
elif [[ "$go_online_version" != "$go_system_version" ]]; then
    echo -e "Installing Golang latest version"
    eval wget https://dl.google.com/go/${go_online_version}.linux-amd64.tar.gz $debug_std
    sudo tar -C /usr/local -xzf ${go_online_version}.linux-amd64.tar.gz && rm -rf ${go_online_version}.linux-amd64.tar.gz $debug_std
    export GOROOT=/usr/local/go
    export GOPATH=$HOME/go
    export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
    echo -e "\n#Golang Variable" >> ~/.bashrc
    echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bashrc
    source ~/.bashrc
fi


printf "${bblue}Installing Golang tools (${#gotools[@]})${reset}\n\n"
# go env -w GO111MODULE=auto
go_step=0
for gotool in "${!gotools[@]}"; do
    go_step=$((go_step + 1))
    eval ${gotools[$gotool]} $debug_std
    exit_status=$?
    if [ $exit_status -eq 0 ]
    then
        printf "${yellow}$gotool installed (${go_step}/${#gotools[@]})${reset}\n"
    else
        printf "${red}Unable to install $gotool, try manually (${go_step}/${#gotools[@]})${reset}\n"
    fi
done


printf "${bblue}Installing repositories (${#repos[@]})${reset}\n\n"
repos_step=0
for repo in "${!repos[@]}"; do
    repos_step=$((repos_step + 1))
    eval git clone https://github.com/${repos[$repo]} $tools_dir/$repo $debug_std
    eval cd $tools_dir/$repo $debug_std
    if [ -s "requirements.txt" ]; then
        eval sudo pip3 install -r requirements.txt $debug_std
    fi
    if [ -s "setup.py" ]; then
        eval sudo python3 setup.py install $debug_std
    fi
    if [ "AnalyticsRelationships" = "$repo" ]; then
        eval go build -ldflags "-s -w"
    elif [ "CeWL" = "$repo" ]; then
        eval sudo gem install bundler && bundle install $debug_std
    elif [ "datasploit" = "$repo" ]; then
        eval python3 -m pip install --upgrade --force-reinstall -r requirements.txt $debug_std
    elif [ "EyeWitness" = "$repo" ]; then
        eval EyeWitness/Python/setup/./setup.sh $debug_std
    elif [ "git-secrets" = "$repo" ]; then
        eval make install $debug_std $debug_std
    elif [ "massdns" = "$repo" ]; then
        eval make && sudo make install $debug_std
    elif [ "masscan" = "$repo" ]; then
        eval cd masscan/bin && eval make install $debug_std
    elif [ "resolveDomains" = "$repo" ]; then
        eval go build $debug_std
    elif [ "sqliv" = "$repo" ]; then
        eval sudo python2 setup.py -i $debug_std
    elif [ "urldedupe" = "$repo" ]; then
        eval cmake CMakeLists.txt && make $debug_std
    elif [ "uDork" = "$repo" ]; then
        eval chmod +x uDork.sh
    # elif [ "Sn1per" = "$repo" ]; then
    #     eval bash ./install.sh
    fi
    exit_status=$?
    if [ $exit_status -eq 0 ]
    then
        printf "${yellow}$repo installed (${repos_step}/${#repos[@]})${reset}\n"
    else
        printf "${red}Unable to install $repo, try manually (${repos_step}/${#repos[@]})${reset}\n"
    fi
done


wordlists_Install(){
    printf "${bblue}Downloading Wordlists (${#wordlists[@]})${reset}\n\n"
    wordlist_step=0
    for wordlist in "${!wordlists[@]}"; do
        wordlist_step=$((wordlist_step + 1))
        eval ${wordlists[$wordlist]} $debug_std
        exit_status=$?
        if [ $exit_status -eq 0 ]
        then
            printf "${yellow}$wordlist installed (${wordlist_step}/${#wordlists[@]})${reset}\n"
        else
            printf "${red}Unable to install $wordlist, try manually (${wordlist_step}/${#wordlists[@]})${reset}\n"
        fi
    done
}
wordlists_Install


printf "${bblue}Installing others tools (${#others[@]})${reset}\n\n"
other_step=0
for other in "${!others[@]}"; do
    other_step=$((other_step + 1))
    eval ${others[$other]} $debug_std
    exit_status=$?
    if [ $exit_status -eq 0 ]
    then
        printf "${yellow}$other installed (${other_step}/${#others[@]})${reset}\n"
    else
        printf "${red}Unable to install $other, try manually (${other_step}/${#others[@]})${reset}\n"
    fi
done



double_check(){

    printf "\n\n${bblue}Checking installed tools${reset}\n\n"

    allinstalled=true

    [ -n "$GOPATH" ] || { printf "${bred} [*] GOPATH var        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -n "$GOROOT" ] || { printf "${bred} [*] GOROOT var        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -n "$PATH" ] || { printf "${bred} [*] PATH var        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/degoogle_hunter/degoogle.py" ] || { printf "${bred} [*] degoogle [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/brutespray/brutespray.py" ] || { printf "${bred} [*] brutespray    [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/theHarvester/theHarvester.py" ] || { printf "${bred} [*] theHarvester  [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/fav-up/favUp.py" ] || { printf "${bred} [*] fav-up     [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/Corsy/corsy.py" ] || { printf "${bred} [*] Corsy       [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/testssl.sh/testssl.sh" ] || { printf "${bred} [*] testssl      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/CMSeeK/cmseek.py" ] || { printf "${bred} [*] CMSeeK        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/ctfr/ctfr.py" ] || { printf "${bred} [*] ctfr      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/fuzz_wordlist.txt" ] || { printf "${bred} [*] OneListForAll    [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/xnLinkFinder/xnLinkFinder.py" ] || { printf "${bred} [*] xnLinkFinder      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/commix/commix.py" ] || { printf "${bred} [*] commix        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/getjswords.py" ] || { printf "${bred} [*] getjswords       [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/JSA/jsa.py" ] || { printf "${bred} [*] JSA     [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/cloud_enum/cloud_enum.py" ] || { printf "${bred} [*] cloud_enum        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/ultimate-nmap-parser/ultimate-nmap-parser.sh" ] || { printf "${bred} [*] nmap-parse-output     [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -f "$tools/pydictor/pydictor.py" ] || { printf "${bred} [*] pydictor      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which github-endpoints $debug_std || { printf "${bred} [*] github-endpoints    [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which github-subdomains $debug_std || { printf "${bred} [*] github-subdomains  [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which gospider $debug_std || { printf "${bred} [*] gospider        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which wafw00f $debug_std || { printf "${bred} [*] wafw00f      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which dnsvalidator $debug_std || { printf "${bred} [*] dnsvalidator    [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which gowitness $debug_std || { printf "${bred} [*] gowitness      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which amass $debug_std || { printf "${bred} [*] Amass      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which waybackurls $debug_std || { printf "${bred} [*] Waybackurls  [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which gau $debug_std || { printf "${bred} [*] gau      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which dnsx $debug_std || { printf "${bred} [*] dnsx        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which gotator $debug_std || { printf "${bred} [*] gotator      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which nuclei $debug_std || { printf "${bred} [*] Nuclei        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    [ -d ~/nuclei-templates ] || { printf "${bred} [*] Nuclei templates [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which gf $debug_std || { printf "${bred} [*] Gf            [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which Gxss $debug_std || { printf "${bred} [*] Gxss        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which subjs $debug_std || { printf "${bred} [*] subjs      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which ffuf $debug_std || { printf "${bred} [*] ffuf        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which massdns $debug_std || { printf "${bred} [*] Massdns      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which qsreplace $debug_std || { printf "${bred} [*] qsreplace      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which interlace $debug_std || { printf "${bred} [*] interlace      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which anew $debug_std || { printf "${bred} [*] Anew        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which unfurl $debug_std || { printf "${bred} [*] unfurl        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which crlfuzz $debug_std || { printf "${bred} [*] crlfuzz      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which httpx $debug_std || { printf "${bred} [*] Httpx      [NO INSTALLED]${reset}\n${reset}"; allinstalled=false;}
    which jq $debug_std || { printf "${bred} [*] jq            [NO INSTALLED]${reset}\n${reset}"; allinstalled=false;}
    which notify $debug_std || { printf "${bred} [*] notify        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which dalfox $debug_std || { printf "${bred} [*] dalfox        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which puredns $debug_std || { printf "${bred} [*] puredns      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which unimap $debug_std || { printf "${bred} [*] unimap        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which emailfinder $debug_std || { printf "${bred} [*] emailfinder  [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which analyticsrelationships $debug_std || { printf "${bred} [*] analyticsrelationships    [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which mapcidr $debug_std || { printf "${bred} [*] mapcidr      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which ppfuzz $debug_std || { printf "${bred} [*] ppfuzz        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which searchsploit $debug_std || { printf "${bred} [*] searchsploit    [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which ipcdn $debug_std || { printf "${bred} [*] ipcdn      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which interactsh-client $debug_std || { printf "${bred} [*] interactsh-client  [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which uro $debug_std || { printf "${bred} [*] uro      [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which tlsx $debug_std || { printf "${bred} [*] tlsx        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which bbrf $debug_std || { printf "${bred} [*] bbrf        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which smap $debug_std || { printf "${bred} [*] smap        [NO INSTALLED]\n"; allinstalled=false;}
    which gitdorks_go $debug_std || { printf "${bred} [*] gitdorks_go  [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which ripgen $debug_std || { printf "${bred} [*] ripgen        [NO INSTALLED]${reset}\n"; allinstalled=false;}
    which dsieve $debug_std || { printf "${bred} [*] dsieve        [NO INSTALLED]${reset}\n\n"; allinstalled=false;}

    if [ "${allinstalled}" = true ]; then
        printf "${bgreen}Good! All tools installed!${reset}"
    else
        printf "${yellow}Unable to install these tools try to install manually${reset}"
    fi
}



git clone https://github.com/dwisiswant0/findom-xss.git && cd findom-xss && rm -rf LinkFinder && git clone https://github.com/GerbenJavado/LinkFinder.git && cd LinkFinder && python setup.py install && cd -