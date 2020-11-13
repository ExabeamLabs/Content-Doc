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
    """"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)","({host}[^"]+)"""",
    """"4662"",""({user_sid}[^"]+)"""",
    """"4662",("[^"]*",){1}"({user}[^"]+)"""",
    """"4662",("[^"]*",){2}"({domain}[^"]+)"""",
    """"4662",("[^"]*",){3}"({logon_id}[^"]+)"""",
    """"4662",("[^"]*",){4}"({target_domain}[^"]+)"""",
    """"4662",("[^"]*",){5}"({target_user}[^"]+)"""",
    """"4662",("[^"]*",){6}"({target_user_sid}[^"]+)"""" 
  ]
  DupFields = ["host->dest_host"]
}
```