# PKI_WebShell
Web shell for Microsoft IIS with a Linux Bash Script console. Built-in asymmetric+symmetric cryptography. Provides authentication and protection against mitm/eavesdropping/replay attacks.

## Usage

```
$ ./PKI_WebShell.sh -h
PKI_WebShell by Paul Taylor @bao7uo
  https://github.com/bao7uo/PKI_WebShell
Generate webshell and private key:
  ./PKI_Webshell_Client.sh -g test
Run command:
  ./PKI_Webshell_Client.sh -u https://test.local/test.ashx -k test.priv.key -c 'dir /as c:\'
```

## Contribute
Contributions, feedback and ideas will be appreciated.

## License notice
Copyright (C) 2018 Paul Taylor

See LICENSE file for details.
