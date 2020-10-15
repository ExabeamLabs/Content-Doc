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
  Conditions = [ """Microsoft-Windows-Sysmon""", """Network connection detected:""", """"AccountName":"""" ]
  Fields = [
    """"UtcTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Image":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))""",
    """"TargetFilename":"({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))"""",
    """"Protocol":"({Protocol}[^"]+)""",
    """"Domain":"({domain}[^"]+)""",
    """"AccountName":"({user}[^"]+)""",
    """"ProcessGuid":"({process_guid}[^"]+)""",
    """ProcessId:\s*({pid}\d+)""",
    """"LogonId":"({logon_id}[^"]+)""",
    """"Hostname":"({host}[^"]+)""",
    """"SourceIp":"({src_ip}[a-fA-F\d.:]+)""",
    """"SourceHostname":"({src_host}[^"]+)""",
    """"SourcePort":"({src_port}\d+)""",
    """"DestinationIp":"({dest_ip}[a-fA-F\d.:]+)""",
    """"DestinationHostname":"({dest_host}[^"]+)""",
    """"DestinationPort":"({dest_port}\d+)""",
    """"Image":"({process}({directory}[^"]*?[\\\/]+)?({process_name}[^"\\\/]+))"""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory", "process->path" ]
}
```