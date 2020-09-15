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
    """Account Name(:|=)\s*({user}[^\s]+)""",
    """Security ID(:|=)\s*({user_sid}[^\s]+)""",
    """Account Domain(:|=)\s*({domain}[^\s]+)""",
    """Logon ID(:|=)\s*({logon_id}[^\s]+)""",
    """Directory Service:\s*Name(:|=)\s*({service_name}[^\s]+)\s*.*?Type(:|=)\s*({service_type}.*?Services)""",
    """GUID(:|=)\s*\{({guid}[^\}]+)""",
    """Operation:\s*Correlation ID(:|=)\s*\{({correlation_id}[^\}]+)""",
    """Object:\s*DN(:|=)\s*({object_dn}.+?)\s""",
    """Object:\s*.*?Class(:|=)\s*({object_class}[^\s]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```