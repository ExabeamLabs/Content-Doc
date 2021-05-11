#### Parser Content
```Java
{
Name = raw-4662-2
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "object-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [""""An operation was performed on an object",""", ""","4662",""" ]
  Fields = [
    """({event_name}An operation was performed on an object)""",
    """"({event_code}4662)"""",
    """"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)","({host}[^"]+)"""",
    """"4662"",""({user_sid}[^"]+)"""",
    """"4662",("[^"]*",){1}"({user}[^"]+)"""",
    """"4662",("[^"]*",){2}"({domain}[^"]+)"""",
    """"4662",("[^"]*",){3}"({logon_id}[^"]+)"""",
    """"4662",("[^"]*",){4}"({target_domain}[^"]+)"""",
    """"4662",("[^"]*",){5}"({target_user}[^"]+)"""",
    """"4662",("[^"]*",){6}"({target_user_sid}[^"]+)"""",
    """"(An operation was performed on an object)",("[^"]+",){2}"({object_class}[^"]+)""",
    """"(An operation was performed on an object)",("[^"]+",){3}"({object}[^"]+)""",
    """"(An operation was performed on an object)",("[^"]+",){4}"({activity_type}[^"]+)""",
    """"(An operation was performed on an object)",("[^"]+",){5}"(LOCAL SERVICE|({user}[^"]+))""",
    """"(An operation was performed on an object)",("[^"]+",){6}"({logon_id}[^"]+)""",
    """"(An operation was performed on an object)",("[^"]+",){7}"(NT AUTHORITY|({domain}[^"]+))""",
    """"(An operation was performed on an object)",("[^"]+",){8}"({activity}[^"]+)""",
    """"(An operation was performed on an object)",("[^"]+",){9}"[\\ntr-]*(-|({properties}[^"]+))""",
    """"(An operation was performed on an object)",("[^"]+",){10}"[\\ntr-]*({attribute}[^"]+?)[trn\s\\]*(<\/Message>|")""",
    """"(An operation was performed on an object)",("[^"]+",){12}"({outcome}[^"]+)"""
  ]
  DupFields = ["host->dest_host"]
}
```