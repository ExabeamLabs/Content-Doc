#### Parser Content
```Java
{
Name = cef-servicenow-file-operation-2
  Vendor = ServiceNow
  Product = ServiceNow
  Lms = ArcSight
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""destinationServiceName =ServiceNow""", """"sys_created_on"""", """"sys_created_by""""]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"sys_created_on":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({app}ServiceNow)""",
    """"srcip":"({src_ip}[^"]{1,2000})""",
    """"name":"({object}[^"]{1,2000})",""",
    """"user(_name)?":"(anonymous|system|({user}[^"\s@]{1,2000}))"""",
    """"user(_name)?":"(anonymous|system|({user_email}[^"\s@]{1,2000}@({email_domain}[^"\s@]{1,2000})))"""",
    """CEF:([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """"queue":"({activity}[^"]{1,2000})""",
    """"parm1":"{1,20}\s{0,100}(|-|({resource}[^"]{1,2000}?))\s{0,100}",""",
    """"(instance|documentkey)":"({object}[^"]{1,2000}?)",""",
    """"tablename":"({table_name}[^"]{1,2000})",""",
    """"table":"({table}[^"]{1,2000})",""",
    """dproc=({event_name}[^=]{1,2000}?)(\s\w+=|$)""",
    """msg=({additional_info}[^=]{1,2000}?)(\s\w+=|$)""",
    """"parm2":"\s{0,100}({action}[^"]{1,2000}?)\s{0,100}",""",
    """"file_name":"({file_name}[^"]{1,2000}?(\.({file_ext}[^\."]{1,2000}))?)",""",
    """"size_bytes":"({bytes}\d{1,100})""",
    """"content_type":"({file_type}[^"]{1,2000}?)",""",
    """"oldvalue":"\s{0,100}({old_value}[^"]{1,2000}?)\s{0,100}",""",
    """newvalue"{1,20}:"\s{0,100}({new_value}[^"]{1,2000}?)\s{0,100}",""",
  ]
  DupFields = [ "host->dest_host", "file_name->object", "activity->accesses" ]


}
```