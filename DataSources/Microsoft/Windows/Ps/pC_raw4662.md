#### Parser Content
```Java
{
Name = raw-4662
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "object-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["""An operation was performed on an object"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """({event_name}An operation was performed on an object)""",
    """hostname=({host}[^=]{1,2000}?),\s{0,100}\w+=""",
    """ip=\[({dest_ip}[a-fA-F0-9.:]{1,2000})""",
    """({event_code}4662)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s{1,100}""",
    """Security ID:\s{0,100}(|({user_sid}.+?))(\\n){0,20}\s{0,100}Account Name:""",
    """Account Name:\s{0,100}(({user_fullname}[^:]{1,2000}?\s[^\s]{1,2000}?)|({user}[^\:]{1,2000}?))(\\n){0,20}\s{0,100}Account Domain:""",
    """Account Domain:\s{0,100}(|({domain}.+?))(\\n){0,20}\s{0,100}Logon ID:""",
    """Object Server:\s{0,100}(|({object_class}.+?))(\\n){0,20}\s{0,100}Object Type:""",
    """Object Type:\s{0,100}(|({object_type}.+?))(\\n){0,20}\s{0,100}Object Name:""",
    """Object Name:\s{0,100}(|({object}.+?))(\\n){0,20}\s{0,100}Handle ID:""",
    """Logon ID:\s{0,100}({logon_id}[^:]{1,2000}?)[\\n\s]{0,20}Object:""",
    """Operation Type:\s{0,100}({activity}.+?)(\\n){0,20}\s{1,100}Accesses:""",
    """Properties:\s{0,100}({properties}.+?)(\\n){0,20}\s{0,100}Additional""",
    """Additional Information:\s{0,100}({attribute}.*?)(\\n){0,20}\s{0,100}""", 
  ]


}
```