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
    """Subject:.+?Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """Object:.+?Class:\s+({object_class}.+?)\s+Operation:""",
    """Object:\s+DN:\s+({object_dn}.+?)\s+GUID:""",
    """Object:\s+DN:.+?({object_ou}OU.+?)\s+GUID:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```