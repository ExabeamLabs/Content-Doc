#### Parser Content
```Java
{
Name = exalms-567
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-567"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"event_id":567,""", "Object Access Attempt:" ,""""@timestamp"""" ]
  Fields = [
    """({event_name}Object Access Attempt)""",
    """"@timestamp"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"computer_name"\s*:\s*"({host}.+?)"""",
    """"record_number"\s*:\s*"({record_id}\d+)""",
    """({event_code}567)""",
    """"user"\s*:\s*\{[^\}]*"identifier"\s*:\s*"({user_sid}[^"]+)""",
    """"user"\s*:\s*\{[^\}]*"name"\s*:\s*"({user}[^"]+)""",
    """"user"\s*:\s*\{[^\}]*"domain"\s*:\s*"({domain}[^"]+)""",
    """"(param3|ObjectType)"\s*:\s*"({file_type}[^"]+)""",
    """"(param5|ObjectName)"\s*:\s*"({file_path}[^"]+)""",
    """"(param5|ObjectName)"\s*:\s*"([^"]*\\)?({file_name}[^\\\."]+(\.({file_ext}[^\.\\"]+))?)"""",
    """"(param5|ObjectName)"\s*:\s*"({file_parent}.+?)\\+[^\\]+"""",
    """"(param6|Accesses)"\s*:\s*"({accesses}.+?)"""",
  ]
  DupFields = [ "host->dest_host" ]
}

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