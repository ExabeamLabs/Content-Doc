#### Parser Content
```Java
{
Name = exalms-576
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"Special privileges assigned to new logon""", """"event_id":576""", """"@timestamp""""]
  Fields = [
    """({event_name}Special privileges assigned to new logon)""",
    """"@timestamp"\s{0,100}:\s{0,100}"({time}[^"]{1,2000})"""",
    """"(?:winlog\.)?computer_name"\s{0,100}:\s{0,100}"({host}[\w\-\.]{1,2000})""",
    """({event_code}576)""",
    """({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """({environment_privilege}SeSystemEnvironmentPrivilege)""",
    """({debug_privilege}SeDebugPrivilege)""",
    """({tcb_privilege}SeTcbPrivilege)""",
    """"record_number"\s{0,100}:\s{0,100}"({record_id}\d{1,100})"""",
    """"user"\s{0,100}:\s{0,100}\{.*?"identifier"\s{0,100}:\s{0,100}"({user_sid}[^"]{1,2000})"""",
    """"user"\s{0,100}:\s{0,100}\{.*?"domain":"({domain}[^"]{1,2000})"""",
    """"user"\s{0,100}:\s{0,100}\{.*?"name":"({user}[^"]{1,2000})"""",
    """"(param4|Privileges)"\s{0,100}:\s{0,100}"({privileges}[^"]{1,2000})"""",
    """"(param3|LogonID|logon_id)"\s{0,100}:\s{0,100}"(-|({logon_id}.+?))\s{0,100}"""",
    """"(param3|LogonID|logon_id)"\s{0,100}:\s{0,100}"\(([^,\s]{1,2000}(,|\s))?(-|({logon_id}.+?)\))"""",
  ]
  DupFields = ["host->dest_host"]


}
```