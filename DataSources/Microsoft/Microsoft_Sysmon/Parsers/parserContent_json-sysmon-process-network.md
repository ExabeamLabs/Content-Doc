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
    """"TargetFilename":"({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))"""",
    """"Protocol":"({Protocol}[^"]+)""",
    """"Domain":"(NT AUTHORITY|({domain}[^"]+))""",
    """"AccountName":"((?i)SYSTEM|({user}[^"]+))""",
    """"ProcessGuid":"({process_guid}[^"]+)""",
    """ProcessId:\s{0,100}({pid}\d{1,100})""",
    """"LogonId":"({logon_id}[^"]+)""",
    """"Hostname":"({host}[^"]+)""",
    """"SourceIp":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"SourceHostname":"(-|({src_host}[^"]+))""",
    """"SourcePort":"({src_port}\d{1,100})""",
    """"DestinationIp":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"DestinationHostname":"({dest_host}[^"]+)""",
    """"DestinationPort":"({dest_port}\d{1,100})""",
    """"EventID":({event_code}\d{1,100})""",
    """"User":"((NT AUTHORITY|({domain}[^\\]+))[\\]+)?((?i)SYSTEM|({user}[^"]+))""""
    """"Image":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```