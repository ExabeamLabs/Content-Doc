#### Parser Content
```Java
{
Name = json-sysmon-process-network
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Direct
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Sysmon""", """Network connection detected""", """"AccountName":"""" ]
  Fields = [
    """"UtcTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"TargetFilename":"({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?))"""",
    """"Protocol":"({Protocol}[^"]{1,2000})""",
    """"Domain":"(NT AUTHORITY|({domain}[^"]{1,2000}))""",
    """"AccountName":"((?i)SYSTEM|({user}[^"]{1,2000}))""",
    """"ProcessGuid":"({process_guid}[^"]{1,2000})""",
    """ProcessId:\s{0,100}({pid}\d{1,100})""",
    """"LogonId":"({logon_id}[^"]{1,2000})""",
    """"Hostname":"({host}[^"]{1,2000})""",
    """"SourceIp":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"SourceHostname":"(-|({src_host}[^"]{1,2000}))""",
    """"SourcePort":"({src_port}\d{1,100})""",
    """"DestinationIp":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"DestinationHostname":"({dest_host}[^"]{1,2000})""",
    """"DestinationPort":"({dest_port}\d{1,100})""",
    """"EventID":({event_code}\d{1,100})""",
    """"User":"((NT AUTHORITY|({domain}[^\\]{1,2000}))[\\]{1,2000})?((?i)SYSTEM|({user}[^"]{1,2000}))""""
    """"Image":"({process}({directory}[^"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"\\\/]{1,2000}))"""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```