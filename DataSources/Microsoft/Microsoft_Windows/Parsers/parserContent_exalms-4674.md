#### Parser Content
```Java
{
Name = exalms-4674
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """An operation was attempted on a privileged object.""", """"event_id":4674""", """"@timestamp""""]
  Fields = [
    """({event_name}An operation was attempted on a privileged object)""",
    """"@timestamp"\s*:\s*"({time}.+?)"""",
    """"hostname":"({host}[^."]*)""",
    """"host":"({src_ip}[A-Fa-f:\d.]+)""",
    """({event_code}4674)""",
    """"keywords":\["({outcome}.+?)"\]""",
    """process_name":"(?: |({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+?)))"""",
    """"(SubjectUserName)"\s*:\s*"(-|({user}.+?))\s*"""",
    """"(SubjectDomainName)"\s*:\s*"(-|({domain}.+?))\s*"""",
    """"(SubjectLogonId)"\s*:\s*"(-|({logon_id}.+?))\s*"""",
    """"(ObjectServer)"\s*:\s*"(-|({object_server}.+?))\s*"""",
    """"(ObjectType)"\s*:\s*"(-|({object_type}.+?))\s*"""",
    """"(ObjectName)"\s*:\s*"(-|({object}.+?))\s*"""",
    """"(AccessMask)"\s*:\s*"(-|({accesses}\d*))\s*"""",
    """"(PrivilegeList)"\s*:\s*"(-|({privileges}.+?))\s*"""",
    """({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """record_number"\s*:\s*"({record_id}\d+)"""
  ]
  DupFields = ["host->dest_host", "directory->process_directory"]
}
```