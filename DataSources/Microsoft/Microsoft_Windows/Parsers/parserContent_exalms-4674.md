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
    """"@timestamp"\s{0,100}:\s{0,100}"({time}.+?)"""",
    """"hostname":"({host}[^."]{0,2000})""",
    """"host":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """({event_code}4674)""",
    """"keywords":\["({outcome}.+?)"\]""",
    """process_name":"(?: |({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}?)))"""",
    """"(SubjectUserName)"\s{0,100}:\s{0,100}"(-|({user}.+?))\s{0,100}"""",
    """"(SubjectDomainName)"\s{0,100}:\s{0,100}"(-|({domain}.+?))\s{0,100}"""",
    """"(SubjectLogonId)"\s{0,100}:\s{0,100}"(-|({logon_id}.+?))\s{0,100}"""",
    """"(ObjectServer)"\s{0,100}:\s{0,100}"(-|({object_server}.+?))\s{0,100}"""",
    """"(ObjectType)"\s{0,100}:\s{0,100}"(-|({object_type}.+?))\s{0,100}"""",
    """"(ObjectName)"\s{0,100}:\s{0,100}"(-|({object}.+?))\s{0,100}"""",
    """"(AccessMask)"\s{0,100}:\s{0,100}"(-|({accesses}\d{0,100}))\s{0,100}"""",
    """"(PrivilegeList)"\s{0,100}:\s{0,100}"(-|({privileges}.+?))\s{0,100}"""",
    """({ownership_privilege}SeTakeOwnershipPrivilege)""",
    """record_number"\s{0,100}:\s{0,100}"({record_id}\d{1,100})"""
  ]
  DupFields = ["host->dest_host", "directory->process_directory"]
}
```