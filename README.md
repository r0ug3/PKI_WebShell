# PKI_WebShell
Web shell with built-in asymmetric+symmetric cryptography. Provides authentication and protection against mitm/eavesdropping/replay attacks.

```
$ ./PKI_WebShell.sh -h
PKI_WebShell by Paul Taylor @bao7uo
  https://github.com/bao7uo/PKI_WebShell
Generate webshell and private key:
  ./PKI_Webshell_Client.sh -g test
Run command:
  ./PKI_Webshell_Client.sh -u https://test.local/test.ashx -k test.priv.key -c 'dir /as c:\'
  ```
