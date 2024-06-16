# Security-Software-Process-and-Driver-Names
Security Software Driver Names and Process Names, please send pull requests in case you want to add more to this list such as registry keys or any other identifiers of AV's, EDR/XDR's or other security products.

If you wish to contribute, please edit the JSON file, we will update the readme.md accordingly for every update. You can also just create an issue with suggestions. just name the Solution, Process/Service Name(s), Driver Name(s) and we will list it here.

# Security Software Process and Driver Information

## AV (Antivirus / Antimalware)

| Solution                          | Process Name(s)                       | Driver Name(s)            | Kernel Mode |
|-----------------------------------|---------------------------------------|---------------------------|-------------|
| Symantec Endpoint Protection      | ccSvcHst.exe, Smc.exe                 | SRTSP.sys, SymEFA.sys     | Y           |
| McAfee Endpoint Security          | mfetp.exe, mfeesp.exe                 | mfewfpk.sys, mfeavfk.sys  | Y           |
| Sophos Intercept X                | SAVService.exe, SAVAdminService.exe   | saviorsys.sys, hmpalert.sys | Y        |
| Bitdefender GravityZone           | EPConsole.exe, bdservicehost.exe      | trufos.sys                | Y           |
| ESET Endpoint Security            | ekrn.exe                              | ehdrv.sys                 | Y           |
| Malwarebytes Endpoint Protection  | mbamservice.exe                       | MBAMSwissArmy.sys         | Y           |
| Webroot SecureAnywhere            | WRSA.exe                              | WRkrn.sys                 | Y           |
| Avast Business Antivirus          | AvastSvc.exe, AvastUI.exe             | aswSP.sys                 | Y           |
| Kaspersky Endpoint Security       | avp.exe                               | klif.sys, klhk.sys        | Y           |
| F-Secure Protection Service       | F-Secure.exe                          | fses.sys                  | Y           |
| VIPRE Advanced Security           | SBAMSvc.exe                           | SBREDrv.sys               | Y           |
| Panda Adaptive Defense            | PSANHost.exe, PSUAService.exe         | PSINFile.sys, PSINProc.sys | Y         |
| G Data Endpoint Protection        | GDataAVK.exe, AVKService.exe          | GDKBFlt64.sys             | Y           |
| Emsisoft Enterprise Security      | a2service.exe                         | a2dskm.sys                | Y           |
| Dr.Web Enterprise Security Suite  | dwservice.exe                         | dwprot.sys                | Y           |
| ZoneAlarm Anti-Ransomware         | ZAPrivacyService.exe                  | ZAPrivacy.sys             | Y           |
| BullGuard Endpoint Security       | BullGuardSvc.exe                      | BgLiveKern.sys            | Y           |
| Avira Antivirus Pro               | avguard.exe                           | avgntflt.sys              | Y           |
| AhnLab V3 Endpoint Security       | V3Svc.exe                             | V3Monitor.sys             | Y           |
| Trend Micro Apex One              | ntrtscan.exe, pccntmon.exe            | TmXPFlt.sys, TMEBC64.sys  | Y           |
| Comodo Advanced Endpoint Protection | cmdagent.exe                         | cmdguard.sys              | Y           |
| SecureAPlus                        | SecureAPlus.exe                       | SecureAPlus.sys           | Y           |
| Heimdal Security Thor             | HeimdalClientHost.exe                 | HeimdalSecureDNS.sys      | Y           |
| Trustwave Endpoint Protection     | TrustwaveService.exe                  | Trustwave.sys             | Y           |
| Cybereason Active Monitoring      | CybereasonRansomFreeService.exe       | Cybereason.sys            | Y           |
| Deep Instinct                     | DeepInstinctService.exe               | DeepInstinct.sys          | Y           |
| Microsoft Defender Antivirus      | MsMpEng.exe                           | WdFilter.sys wdk.sys      | Y           |
| Bitdefender Antivirus Plus        | bdservicehost.exe                     | trufos.sys                | Y           |
| Norton Security                   | nortonsecurity.exe                    | nortonsecurity.sys        | Y           |
| AVG Antivirus                     | avgsvc.exe                            | avgmfx64.sys              | Y           |
| Trend Micro Maximum Security      | TMASOAgent.exe                        | tmaso.sys                 | Y           |
| Quick Heal Total Security         | qhepsvc.exe                           | qhdisk.sys                | Y           |
| Trend Micro OfficeScan            | ntrtscan.exe                          | TmXPFlt.sys               | Y           |
| F-Secure Client Security          | F-Secure.exe                          | fses.sys                  | Y           |
| McAfee Total Protection           | mcshield.exe                          | mfehidk.sys               | Y           |
| Norton 360                        | n360.exe                              | n360drv.sys               | Y           |
| Avast                             | aswidsagent.exe                       | aswids.sys                | Y           |
| Absolute Persistence              | acnamagent.exe, acnamlogonagent.exe   | absolutepersistence.sys   | N           |
| Bitdefender Total Security        | bdagent.exe, vsserv.exe               | bdts.sys                  | Y           |
| Trend Micro Antivirus             | clientcommunicationservice.exe        | trendmicro.sys            | Y           |
| Avira                             | avgnt.exe                             | avgntflt.sys              | Y           |
| Kaspersky                         | klwtblfs.exe                          | klif.sys                  | Y           |
| ESET NOD32                        | egui.exe, ekrn.exe                    | ehdrv.sys                 | Y           |
| McAfee VirusScan                  | mcshield.exe, shstat.exe              | mfehidk.sys               | Y           |
| Panda Security                    | panda_url_filtering.exe, pavfnsvr.exe, pavsrv.exe, psanhost.exe | pavdrv.sys | Y     |
| Sophos Endpoint Security          | savservice.exe, sophosav.exe, sophosclean.exe, sophoshealth.exe, sophossps.exe, sophosui.exe | sophos.sys | Y |
| Windows Defender                  | windefend.exe                         | WdFilter.sys              | Y           |
| Altiris Symantec                  | ccSvcHst.exe                          | atrsdfw.sys               | Y           |
| Cisco AMP                         | sfc.exe                               | csacentr.sys, csaenh.sys, csareg.sys, csascr.sys, csaav.sys, csaam.sys | Y |

## EDR/XDR/IDR/IPS/IDS

| Solution                          | Process Name(s)                       | Driver Name(s)            | Kernel Mode |
|-----------------------------------|---------------------------------------|---------------------------|-------------|
| CrowdStrike Falcon                | CSFalconService.exe                   | csagent.sys               | Y           |
| Carbon Black (VMware)             | cb.exe, cbdefense.exe                 | carbonblackk.sys, cbk7.sys| Y           |
| SentinelOne                       | SentinelAgent.exe, sentinelctl.exe, sentinelmemoryscanner.exe, sentinelservicehost.exe, sentinelstaticengine.exe, sentinelstaticenginescanner.exe | sentinel.sys | Y |
| Microsoft Defender for Endpoint (MDE) | SenseCncProxy.exe, MsSense.exe       | wdboot.sys, wdfilter.sys, WdNisDrv.sys | Y |
| Symantec Endpoint Detection and Response | SescLU.exe, seplu.exe               | SescDrv.sys               | Y           |
| McAfee Endpoint Detection and Response | mfefire.exe, mfeepmpk.exe           | mfehidk.sys               | Y           |
| Sophos Intercept X                | SAVService.exe, SAVAdminService.exe   | saviorsys.sys, hmpalert.sys | Y         |
| Bitdefender GravityZone           | EPConsole.exe, bdservicehost.exe      | trufos.sys                | Y           |
| ESET Endpoint Security            | ekrn.exe                              | ehdrv.sys                 | Y           |
| Malwarebytes Endpoint Protection  | mbamservice.exe                       | MBAMSwissArmy.sys         | Y           |
| Webroot SecureAnywhere            | WRSA.exe                              | WRkrn.sys                 | Y           |
| Avast Business Antivirus          | AvastSvc.exe, AvastUI.exe             | aswSP.sys                 | Y           |
| Kaspersky Endpoint Security       | avp.exe                               | klif.sys, klhk.sys        | Y           |
| FireEye Endpoint Security         | xagt.exe                              | fe_sysmon.sys             | Y           |
| Cisco AMP for Endpoints           | sfc.exe, CylanceSvc.exe               | cylance.sys               | Y           |
| Palo Alto Networks Traps          | CyveraService.exe, CyveraConsole.exe, traps.exe, trapsagent.exe, trapsd.exe | cyverak.sys | Y |
| Trend Micro Apex One              | ntrtscan.exe, pccntmon.exe            | TmXPFlt.sys, TMEBC64.sys  | Y           |
| Sophos XDR                        | SAVService.exe, SAVAdminService.exe   | saviorsys.sys, hmpalert.sys | Y         |
| Check Point SandBlast Agent       | TracSrvWrapper.exe, cpda.exe          | cpprotect.sys             | Y           |
| Comodo Advanced Endpoint Protection | cmdagent.exe                         | cmdguard.sys              | Y           |
| Cybereason Defense Platform       | CybereasonRansomFreeService.exe       | Cybereason.sys            | Y           |
| Elastic Endpoint Security         | elastic-endpoint.exe                  | elastic-endpoint.sys      | Y           |
| BlackBerry Optics                 | CylanceSvc.exe                        | cylance.sys               | Y           |
| VMware Workspace ONE              | AirWatchService.exe                   | aw_vbfilter.sys           | Y           |
| RSA NetWitness Endpoint           | nwservice.exe                         | nwkernel.sys              | Y           |
| McAfee MVISION Endpoint           | MfeEpeHost.exe                        | MfeEpePc.sys              | Y           |
| ArcSight ESM                      | arcsight.exe                          | arcsightdrv.sys           | Y           |
| Ivanti Endpoint Security          | HeatSoftware.exe                      | HeatSys.sys               | Y           |
| ZoneAlarm Anti-Ransomware         | ZAPrivacyService.exe                  | ZAPrivacy.sys             | Y           |
| G Data Endpoint Protection        | GDataAVK.exe, AVKService.exe          | GDKBFlt64.sys             | Y           |
| Emsisoft Enterprise Security      | a2service.exe                         | a2dskm.sys                | Y           |
| Dr.Web Enterprise Security Suite  | dwservice.exe                         | dwprot.sys                | Y           |
| Heimdal Security Thor             | HeimdalClientHost.exe                 | HeimdalSecureDNS.sys      | Y           |
| SecureAPlus                        | SecureAPlus.exe                       | SecureAPlus.sys           | Y           |
| AhnLab V3 Endpoint Security       | V3Svc.exe                             | V3Monitor.sys             | Y           |
| Trustwave Endpoint Protection     | TrustwaveService.exe                  | Trustwave.sys             | Y           |
| BullGuard Endpoint Security       | BullGuardSvc.exe                      | BgLiveKern.sys            | Y           |
| Avira Antivirus Pro               | avguard.exe                           | avgntflt.sys              | Y           |
| FortiEDR (Fortinet)               | fdedr.exe                             | fdedrdrv.sys              | Y           |
| Cynet 360                         | cyserver.exe                          | cyndrv.sys                | Y           |
| BlackBerry Protect                | BlackBerryProtect.exe                 | BlackBerryDrv.sys         | Y           |
| CrowdStrike Falcon Complete       | CSFalconService.exe                   | csfalcondrv.sys           | Y           |
| Rapid7 InsightIDR                 | rapid7.exe                            | rapid7drv.sys             | Y           |
| Cisco Umbrella Roaming Security   | aciseagent.exe, acumbrellaagent.exe   | umbrella.sys              | Y           |
| Trend Micro EDR                   | appcontrolagent.exe, browserexploitdetection.exe, dataprotectionservice.exe, endpointbasecamp.exe, realtime scanservice.exe, samplingservice.exe, securityagentmonitor.exe | trendmicroedr.sys | Y |
| Darktrace                         | darktracetsa.exe                      | darktrace.sys             | Y           |
| DriveSentry                       | dsmonitor.exe, dwengine.exe           | drivesentry.sys           | Y           |
| Cytomic Orion                     | cytomicendpoint.exe                   | cytomic.sys               | Y           |
| Tanium EDR                        | tanclient.exe                         | tanium.sys                | Y           |
| Altiris Symantec                  | ccSvcHst.exe                          | atrsdfw.sys               | Y           |
| Dell Secureworks                  | secureworks.exe                       | groundling32.sys, groundling64.sys | Y |
| Endgame                           | endgame.exe                           | esensor.sys               | Y           |
| FireEye                           | fireeye.exe                           | FeKern.sys, WFP_MRT.sys   | Y           |
| F-Secure                          | fsecure.exe                           | xfsgk.sys, fsatp.sys, fshs.sys | Y    |
| Hexis Cyber Solutions             | hexis.exe                             | HexisFSMonitor.sys        | Y           |
| Sophos                            | savservice.exe                        | SAVOnAccess.sys, savonaccess.sys, sld.sys | Y |
| Symantec                          | symantec.exe                          | pgpwdefs.sys, GEProtection.sys, diflt.sys, sysMon.sys, ssrfsf.sys, emxdrv2.sys, reghook.sys, spbbcdrv.sys, bhdrvx86.sys, bhdrvx64.sys, SISIPSFileFilter.sys, symevent.sys, vxfsrep.sys, VirtFile.sys, SymAFR.sys, symefasi.sys, symefa.sys, symefa64.sys, SymHsm.sys, evmf.sys, GEFCMP.sys, VFSEnc.sys, pgpfs.sys, fencry.sys, symrg.sys | Y |
| McAfee                            | mcafee.exe                            | mfeaskm.sys, mfencfilter.sys | Y     |
| Raytheon Cyber Solutions          | raytheon.exe                          | eaw.sys                   | Y           |
| SAFE-Cyberdefense                 | safe.exe                              | SAFE-Agent.sys            | Y           |
| Microsoft Defender XDR            | MsSense.exe                           | wdboot.sys, wdfilter.sys, WdNisDrv.sys | Y |

## SIEM Solutions / Log Collectors / Log Forwarders

| Solution                          | Process Name(s)                       | Driver Name(s)            | Kernel Mode |
|-----------------------------------|---------------------------------------|---------------------------|-------------|
| Splunk Universal Forwarder        | splunkd.exe                           | splunkdrv.sys             | Y           |
| IBM QRadar                        | qradar.exe                            | N/A                       | N           |
| LogRhythm SIEM                    | lragent.exe                           | N/A                       | N           |
| ArcSight ESM                      | arcsight.exe                          | arcsightdrv.sys           | Y           |
| AlienVault USM                    | ossec-agent.exe                       | ossec.sys                 | Y           |
| Sumo Logic                        | sumo.exe                              | N/A                       | N           |
| Graylog                           | graylog-agent.exe                     | N/A                       | N           |
| LogPoint                          | logpoint-agent.exe                    | N/A                       | N           |
| SolarWinds SEM                    | SolarWindsSEM.exe                     | N/A                       | N           |
| RSA NetWitness                    | nwservice.exe                         | nwkernel.sys              | Y           |
| Microsoft Sentinel                | MsSense.exe                           | wdboot.sys, wdfilter.sys, WdNisDrv.sys | Y |
| Nexthink                          | nxtusm.exe                            | nxtrdrv.sys, nxtrdrv5.sys | Y           |
| Nexthink Collector                | nxtsvc.exe                            | nxtrdrv.sys, nxtrdrv5.sys | Y           |
| Elastic SIEM                      | elastic-agent.exe                     | elasticdrv.sys            | Y           |
| Devo SIEM                         | devo-agent.exe                        | N/A                       | N           |
| AT&T Cybersecurity USM            | usm-agent.exe                         | usmdrv.sys                | Y           |
| Microsoft Sysmon                  | sysmon.exe, sysmon64.exe              | sysmondrv.sys             | Y           |
| SolarWinds NPM                    | npmdagent.exe                         | solarwinds.sys            | Y           |

## Applockers / PIM Solutions (Privilege Identity Management / Application Locker)

| Solution                          | Process Name(s)                       | Driver Name(s)            | Kernel Mode |
|-----------------------------------|---------------------------------------|---------------------------|-------------|
| CyberArk Endpoint Privilege Manager | epmService.exe                       | epmDriver.sys             | Y           |
| Thycotic Privilege Manager        | DPMService.exe                        | DPMDriver.sys             | Y           |
| BeyondTrust Endpoint Privilege Management | BeyondTrust.exe                    | BeyondTrustDriver.sys     | Y           |
| Ivanti Application Control        | AppSenseService.exe                   | AppSenseDriver.sys        | Y           |
| Microsoft AppLocker               | AppLockerService.exe                  | AppLocker.sys             | Y           |
| Symantec Endpoint Privilege Control | SEPCService.exe                      | SEPCDriver.sys            | Y           |
| ThreatLocker                      | ThreatLockerService.exe               | ThreatLocker.sys          | Y           |
| CyberArk Software                 | epmService.exe                        | CybKernelTracker.sys      | Y           |
| Delinea Secret Server             | SecretServerService.exe               | DelineaDriver.sys         | Y           |
| ManageEngine PAM360               | PAM360Service.exe                     | ManageEngineDriver.sys    | Y           |
| WALLIX Bastion                    | WALLIXService.exe                     | WALLIXDriver.sys          | Y           |
| ARCON PAM                         | ARCONService.exe                      | ARCONDriver.sys           | Y           |
| StrongDM                          | StrongDMService.exe                   | StrongDMDriver.sys        | Y           |
| Symantec PAM                      | SymantecPAMService.exe                | SymantecPAMDriver.sys     | Y           |
| Microsoft Entra ID                | EntraIDService.exe                    | EntraIDDriver.sys         | Y           |

## Network Security & Firewall Solutions

| Solution                          | Process Name(s)                       | Driver Name(s)            | Kernel Mode |
|-----------------------------------|---------------------------------------|---------------------------|-------------|
| Cisco Firepower                   | sfmgr.exe                             | sfkmdrv.sys               | Y           |
| Palo Alto Networks GlobalProtect  | PanGPA.exe                            | pangpd.sys                | Y           |
| Fortinet FortiClient              | FortiTray.exe                         | fortimon.sys              | Y           |
| Check Point Endpoint Security     | TrGUI.exe                             | trdrv.sys                 | Y           |
| Check Point Firewall              | fw.exe                                | checkpointfw.sys          | Y           |
| Kerio Personal Firewall           | kpf4ss.exe                            | kpfdrv.sys                | Y           |
| Agnitum Outpost Firewall          | outpost.exe                           | agnitumfw.sys             | Y           |
| McAfee Endpoint Security Firewall | mfemactl.exe                          | mfeepf.sys                | Y           |

## Complete List of Data Loss Prevention (DLP) Solutions

| Solution                          | Process Name(s)                       | Driver Name(s)            | Kernel Mode |
|-----------------------------------|---------------------------------------|---------------------------|-------------|
| Symantec DLP                      | edpa.exe, wdp.exe                     | dlpf.sys                  | Y           |

