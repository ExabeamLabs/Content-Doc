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
    """"@timestamp"\s{0,100}:\s{0,100}"({time}.+?)"""",
    """"(?:winlog\.)?computer_name"\s{0,100}:\s{0,100}"({host}.+?)"""",
    """"(param8|Dest_host)"\s{0,100}:\s{0,100}"(-|({dest_host}.+?))\s{0,100}"""",
    """"(param9|Dest_Service)"\s{0,100}:\s{0,100}"(-|({dest_service}.+?))\s{0,100}"""",
    """({event_code}552)""",
    """"host":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"(param11|SourceNetworkAddress|source_ip)"\s{0,100}:\s{0,100}"(-|({src_ip}.+?))\s{0,100}"""",
    """"user"\s{0,100}:\s{0,100}\{.*?"domain"\s{0,100}:\s{0,100}"({domain}.+?)"""",
    """"(param1|UserName)"\s{0,100}:\s{0,100}"(-|({user}.+?))\s{0,100}"""",
    """"(param2|Target Domain|domain)"\s{0,100}:\s{0,100}"({domain}.+?)\s{0,100}"""",    
    """"(param7|Target Logon GUID)"\s{0,100}:\s{0,100}"(-|({account_logon_guid}.+?))\s{0,100}"""",
    """"(param10|process_id)"\s{0,100}:\s{0,100}"(-|({process_id}.+?))\s{0,100}"""",
    """"(param5|Target User Name)"\s{0,100}:\s{0,100}"(-|({account}.+?))\s{0,100}"""",
    """"(param6|Target Domain)"\s{0,100}:\s{0,100}"(-|({account_domain}.+?))\s{0,100}"""",
    """"(param3|Logon ID|logon_id)"\s{0,100}:\s{0,100}"(-|({logon_id}.+?))\s{0,100}"""",
    """"(param3|Logon ID|logon_id)"\s{0,100}:\s{0,100}"\(([\dxA-F]{1,2000

}
```