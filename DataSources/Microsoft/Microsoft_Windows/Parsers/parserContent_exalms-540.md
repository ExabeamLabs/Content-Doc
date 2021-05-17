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
    """"@timestamp"\s{0,100}:\s{0,100}"({time}.+?)"""",
    """"(?:winlog\.)?computer_name"\s{0,100}:\s{0,100}"({host}.+?)"""",
    """"event_id"\s{0,100}:\s{0,100}({event_code}\d{1,100})""",
    """"user"\s{0,100}:\s{0,100}\{.*?"domain"\s{0,100}:\s{0,100}"({domain}.+?)"""",
    """"user"\s{0,100}:\s{0,100}\{.*?"name"\s{0,100}:\s{0,100}"({user}.+?)"""",
    """"(param1|UserName)"\s{0,100}:\s{0,100}"({user}.+?)\s{0,100}"""",
    """"(param2|Domain)"\s{0,100}:\s{0,100}"({domain}.+?)\s{0,100}"""",
    """"(param14|SourceNetworkAddress|source_ip)"\s{0,100}:\s{0,100}"({src_ip}.+?)\s{0,100}"""",
    """"(param7|Workstation|workstation_name)"\s{0,100}:\s{0,100}"({src_host_windows}.+?)\s{0,100}"""",
    """"(param7|Workstation|workstation_name)"\s{0,100}:\s{0,100}"({src_host}[^"]{1,2000}).*?Source Network Address:(\\t)*-[\\n\\t]{1,2000}""",
    """"(param5|LogonProcess)"\s{0,100}:\s{0,100}"({auth_process}.+?)\s{0,100}"""",
    """"(param6|AuthenticationPackage|authentication_package)"\s{0,100}:\s{0,100}"({auth_package}.+?)\s{0,100}"""",
    """"(param3|LogonId|logon_id)"\s{0,100}:\s{0,100}"({logon_id}.+?)\s{0,100}"""",
    """"(param3|LogonId|logon_id)"\s{0,100}:\s{0,100}"\(([\dxA-F]{1,2000}
```