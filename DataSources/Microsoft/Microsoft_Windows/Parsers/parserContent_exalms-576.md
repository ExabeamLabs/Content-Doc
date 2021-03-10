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
    """"@timestamp"\s*:\s*"({time}[^"]+)"""",
    """"computer_name"\s*:\s*"({host}[\w\-\.]+)""",
    """({event_code}576)""",
    """({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """({environment_privilege}SeSystemEnvironmentPrivilege)""",
    """({debug_privilege}SeDebugPrivilege)""",
    """({tcb_privilege}SeTcbPrivilege)""",
    """"record_number"\s*:\s*"({record_id}\d+)"""",
    """"user"\s*:\s*\{.*?"identifier"\s*:\s*"({user_sid}[^"]+)"""",
    """"user"\s*:\s*\{.*?"domain":"({domain}[^"]+)"""",
    """"user"\s*:\s*\{.*?"name":"({user}[^"]+)"""",
    """"(param4|Privileges)"\s*:\s*"({privileges}[^"]+)"""",
    """"(param3|LogonID|logon_id)"\s*:\s*"(-|({logon_id}.+?))\s*"""",
    """"(param3|LogonID|logon_id)"\s*:\s*"\(([^,\s]+(,|\s))?(-|({logon_id}.+?)\))"""",
  ]
  DupFields = ["host->dest_host"]
}
```