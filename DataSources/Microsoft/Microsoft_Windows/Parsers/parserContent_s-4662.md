#### Parser Content
```Java
{
Name = s-4662
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "object-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [""",4662,""", """An operation was performed on an object"""]
  Fields = [
    """({event_name}An operation was performed on an object)""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100}),""",
    """({outcome}(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)),({host}[^\s,]{1,2000})""",
    """Account Name:\s{0,100}({user}.+?)\s{0,100}Account Domain""",
    """Account Domain:\s{0,100}({domain}.+?)\s{0,100}Logon ID""",
    """Logon ID:\s{0,100}({logon_id}[^\s]{1,2000})""",
    """Object Server:\s{0,100}({object_class}.+?)\s{0,100}Object Type:""",
    """Object Type:\s{0,100}({object_type}.+?)\s{0,100}Object Name:""",
    """Object Name:\s{0,100}({object}.+?)\s{0,100}Handle ID:""",
    """Operation Type:\s{0,100}({action}.+?)\s{0,100}Accesses:""",
    """Properties:\s{0,100}(?:-|({properties}.+?))\s{0,100}Additional Information:""",
    """Additional Information:\s{0,100}({attribute}[^,]{1,2000})""",
    """({event_code}4662)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```