#### Parser Content
```Java
{
Name = raw-4662
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "object-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["""An operation was performed on an object"""]
  Fields = [
    """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
    """({event_name}An operation was performed on an object)""",
    """({event_code}4662)""",
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s{1,100}""",
    """Security ID:\s{0,100}(|({user_sid}.+?))\s{0,100}Account Name:""",
    """Account Name:\s{0,100}(|({user}.+?))\s{0,100}Account Domain:""",
    """Account Domain:\s{0,100}(|({domain}.+?))\s{0,100}Logon ID:""",
    """Object Server:\s{0,100}(|({object_class}.+?))\s{0,100}Object Type:""",
    """Object Type:\s{0,100}(|({activity_type}.+?))\s{0,100}Object Name:""",
    """Object Name:\s{0,100}(|({object}.+?))\s{0,100}Handle ID:""",
    """Logon ID:\s{0,100}({logon_id}[^\s]+)\s""",
    """Operation Type:\s{0,100}({activity}.+?)\s{1,100}Accesses:""",
    """Properties:\s{0,100}({properties}.+?)\s{1,100}Additional""",
    """Additional Information:\s{0,100}({attribute}.+?)\s{0,100}(<\/Message>|\s{1,100}User:|$)"""
  ]
}
```