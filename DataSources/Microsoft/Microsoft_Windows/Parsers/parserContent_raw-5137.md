#### Parser Content
```Java
{
Name = raw-5137
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-ds-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "A directory service object was created", "Object:", "Subject:"  ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({event_name}A directory service object was created)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """({event_code}5137)""",
    """ComputerName=({host}[^\s]+)""",
    """Account Name(:|=)\s{0,100}({user}[^\s]+)""",
    """Security ID(:|=)\s{0,100}({user_sid}[^\s]+)""",
    """Account Domain(:|=)\s{0,100}({domain}[^\s]+)""",
    """Logon ID(:|=)\s{0,100}({logon_id}[^\s]+)""",
    """Directory Service:\s{0,100}Name(:|=)\s{0,100}({service_name}[^\s]+)\s{0,100}.*?Type(:|=)\s{0,100}({service_type}.*?Services)""",
    """GUID(:|=)\s{0,100}\{({guid}[^\}]+)""",
    """Operation:\s{0,100}Correlation ID(:|=)\s{0,100}\{({correlation_id}[^\}]+)""",
    """Object:\s{0,100}DN(:|=)\s{0,100}({object_dn}.+?)\s""",
    """Object:\s{0,100}.*?Class(:|=)\s{0,100}({object_class}[^\s]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```