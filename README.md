# PKI_WebShell
[![Language](https://img.shields.io/badge/Lang-CSharp-blue.svg)](https://docs.microsoft.com/en-us/dotnet/csharp/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

Web shell for Microsoft IIS (.ashx) with a Linux Bash Script console. Built-in asymmetric+symmetric cryptography. Provides authentication and protection against mitm/eavesdropping/replay attacks.

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
