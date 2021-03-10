#### Parser Content
```Java
{
Name = exalms-540
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-540"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"event_id":540""", """Successful Network Logon:""", """"@timestamp"""" ]
  Fields = [
    """({event_name}Successful Network Logon)""",
    """"@timestamp"\s*:\s*"({time}.+?)"""",
    """"computer_name"\s*:\s*"({host}.+?)"""",
    """"event_id"\s*:\s*({event_code}\d+)""",
    """"user"\s*:\s*\{.*?"domain"\s*:\s*"({domain}.+?)"""",
    """"user"\s*:\s*\{.*?"name"\s*:\s*"({user}.+?)"""",
    """"(param1|UserName)"\s*:\s*"({user}.+?)\s*"""",
    """"(param2|Domain)"\s*:\s*"({domain}.+?)\s*"""",
    """"(param14|SourceNetworkAddress|source_ip)"\s*:\s*"({src_ip}.+?)\s*"""",
    """"(param7|Workstation|workstation_name)"\s*:\s*"({src_host_windows}.+?)\s*"""",
    """"(param7|Workstation|workstation_name)"\s*:\s*"({src_host}[^"]+).*?Source Network Address:(\\t)*-[\\n\\t]+""",
    """"(param5|LogonProcess)"\s*:\s*"({auth_process}.+?)\s*"""",
    """"(param6|AuthenticationPackage|authentication_package)"\s*:\s*"({auth_package}.+?)\s*"""",
    """"(param3|LogonId|logon_id)"\s*:\s*"({logon_id}.+?)\s*"""",
    """"(param3|LogonId|logon_id)"\s*:\s*"\(([\dxA-F]+,)?({logon_id}.+?)\)\s*"""",
    """"(param4|LogonType)"\s*:\s*"({logon_type}\d+)\s*"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```