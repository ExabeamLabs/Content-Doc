#### Parser Content
```Java
{
Name = json-cyberark-privileged-object-access
  Vendor = CyberArk
  Product = CyberArk Endpoint Privilege Management
  Lms = Syslog
  DataType = "privileged-object-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"RestrAccessEvent":""", """"setName":"""", """"RestrictedObjectId":"""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[-+]\d\d:\d\d)""",
    """\d\d:\d\d\s({host}[^\s]{1,2000})\sLOGSTASH""",
    """({event_name}RestrAccessEvent)""",
    """"Size"{1,20}:"{1,20}({bytes}[^"]{1,2000})""",
    """"computerName"{1,20}:"{1,20}({src_host}[^"]{1,2000})""",
    """"Description"{1,20}:"{1,20}({additional_info}[^"]{1,2000})""",
    """"PolicyName"{1,20}:"{1,20}({policy}[^"]{1,2000})""",
    """"@user"{1,20}:"{1,20}(({domain}[^"\\]{1,2000})\\+)?({user}[^"\\]{1,2000})"""",
    """"@OsProcessId"{1,20}:"{1,20}({pid}\d{1,100})""",
    """"Path"{1,20}:"{1,20}({process}({process_directory}[^"]{0,2000})\\\\({process_name}[^"]{1,2000}))""",
    """"@allowed"{1,20}:"{1,20}({outcome}[^"]{1,2000})""",
    """"eventId"{1,20}:"{1,20}({event_code}[^"]{1,2000})""",
    """"RestrictedObjectId"{1,20}:"{1,20}\{({object_id}[^"}]{1,2000})""",
  ]


}
```