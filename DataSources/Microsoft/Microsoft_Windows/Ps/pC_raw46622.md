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
    """"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)","({host}[^"]{1,2000})"""",
    """"4662"",""({user_sid}[^"]{1,2000})"""",
    """"4662",("[^"]{0,2000}",){1}"({user}[^"]{1,2000})"""",
    """"4662",("[^"]{0,2000}",){2}"({domain}[^"]{1,2000})"""",
    """"4662",("[^"]{0,2000}",){3}"({logon_id}[^"]{1,2000})"""",
    """"4662",("[^"]{0,2000}",){4}"({target_domain}[^"]{1,2000})"""",
    """"4662",("[^"]{0,2000}",){5}"({target_user}[^"]{1,2000})"""",
    """"4662",("[^"]{0,2000}",){6}"({target_user_sid}[^"]{1,2000})"""",
    """"(An operation was performed on an object)",("[^"]{1,2000}",){2}"({object_class}[^"]{1,2000})""",
    """"(An operation was performed on an object)",("[^"]{1,2000}",){3}"({object}[^"]{1,2000})""",
    """"(An operation was performed on an object)",("[^"]{1,2000}",){4}"({object_type}[^"]{1,2000})""",
    """"(An operation was performed on an object)",("[^"]{1,2000}",){5}"(LOCAL SERVICE|({user}[^"]{1,2000}))""",
    """"(An operation was performed on an object)",("[^"]{1,2000}",){6}"({logon_id}[^"]{1,2000})""",
    """"(An operation was performed on an object)",("[^"]{1,2000}",){7}"(NT AUTHORITY|({domain}[^"]{1,2000}))""",
    """"(An operation was performed on an object)",("[^"]{1,2000}",){8}"({activity}[^"]{1,2000})""",
    """"(An operation was performed on an object)",("[^"]{1,2000}",){9}"[\\ntr-]{0,2000}(-|({properties}[^"]{1,2000}))""",
    """"(An operation was performed on an object)",("[^"]{1,2000}",){10}"[\\ntr-]{0,2000}({attribute}[^"]{1,2000}?)[trn\s\\]{0,2000}(<\/Message>|")""",
    """"(An operation was performed on an object)",("[^"]{1,2000}",){12}"({outcome}[^"]{1,2000})"""
  ]
  DupFields = ["host->dest_host"]
}
```