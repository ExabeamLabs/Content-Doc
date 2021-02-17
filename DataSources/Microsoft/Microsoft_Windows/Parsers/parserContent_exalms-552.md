#### Parser Content
```Java
{
Name = exalms-552
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"event_id":552""", """Logon attempt using explicit credentials:""", """"@timestamp"""" ]
  Fields = [
    """({event_name}Logon attempt using explicit credentials)""",
    """"@timestamp"\s*:\s*"({time}.+?)"""",
    """"(?:winlog\.)?computer_name"\s*:\s*"({host}.+?)"""",
    """"(param8|Dest_host)"\s*:\s*"(-|({dest_host}.+?))\s*"""",
    """"(param9|Dest_Service)"\s*:\s*"(-|({dest_service}.+?))\s*"""",
    """({event_code}552)""",
    """"host":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"(param11|SourceNetworkAddress|source_ip)"\s*:\s*"(-|({src_ip}.+?))\s*"""",
    """"user"\s*:\s*\{.*?"domain"\s*:\s*"({domain}.+?)"""",
    """"(param1|UserName)"\s*:\s*"(-|({user}.+?))\s*"""",
    """"(param2|Target Domain|domain)"\s*:\s*"({domain}.+?)\s*"""",    
    """"(param7|Target Logon GUID)"\s*:\s*"(-|({account_logon_guid}.+?))\s*"""",
    """"(param10|process_id)"\s*:\s*"(-|({process_id}.+?))\s*"""",
    """"(param5|Target User Name)"\s*:\s*"(-|({account}.+?))\s*"""",
    """"(param6|Target Domain)"\s*:\s*"(-|({account_domain}.+?))\s*"""",
    """"(param3|Logon ID|logon_id)"\s*:\s*"(-|({logon_id}.+?))\s*"""",
    """"(param3|Logon ID|logon_id)"\s*:\s*"\(([\dxA-F]+,)?(-|({logon_id}.+?)\))\s*"""",
    """"(param4|Logon GUID)"\s*:\s*"(-|({user_logon_guid}.+?))"""",
    """record_number"\s*:\s*"({record_id}\d+)"""
  ]
}
```