#### Parser Content
```Java
{
Name = raw-5140-2
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "share-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Microsoft-Windows-Security-Auditing""","""AccessList:""", """5140""", """AccessMask:""", """ObjectType:""", """ShareName:""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,3}[+\-]{1,20}\d\d:\d\d""",
    """({host}[^\s]{1,2000})\s{1,100}(File Share|\d{1,100}\s{1,100})""",
    """({event_code}5140)""",
    """SubjectUserName:({user}[^,]{1,2000}),""",
    """SubjectDomainName:({domain}[^,]{1,2000}),""",
    """SubjectLogonId:({logon_id}[^,]{1,2000}),""",
    """ObjectType:({file_type}[^,]{1,2000}),""",
    """IpAddress:(::ffff:)?({src_ip}[a-fA-F\d:.]{1,2000}),""",
    """IpPort:({src_port}\d{1,100}),""",
    """ShareName:(?:\\\\\*\\)?({share_name}[^,]{1,2000}),""",
    """ShareLocalPath:(|({share_path}(({d_parent}[^,]{1,2000}?)\\)?(|({d_name}[^\\,]{1,2000}?)))),""",
    """AccessList:({accesses}[^:]{1,2000}),""",
    """({outcome}(Success|Failure) Audit)"""
  ]
}
```