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
    """"sys_created_on"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({app}ServiceNow)""",
    """"srcip"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
    """"name"{1,20}:"{1,20}({event_name}[^",]{1,2000})""",
    """"user(_name)?"{1,20}:"{1,20}(({user_email}[^@"]{1,2000}@({email_domain}[^.]{1,2000}\.[^"]{1,2000}))|({user}[^",]{1,2000}))""",
    """"queue"{1,20}:"{1,20}({activity}[^",]{1,2000})""",
    """"parm1"{1,20}:"{1,20}\s{0,100}(|-|({resource}[^"]{1,2000}?))\s{0,100}"{1,20

}
```