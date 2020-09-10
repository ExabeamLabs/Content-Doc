#### Parser Content
```Java
{
Name = s-5141
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-ds-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "EventCode=5141", "A directory service object was deleted" ]
  Fields = [
    """({event_name}A directory service object was deleted)""",
    """({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
    """ComputerName=({host}[\w.\-]+)""",
    """EventCode=({event_code}\w+)""",
    """Subject:.+?Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """Object:.+?Class:\s+({object_class}.+?)\s+Operation:""",
    """Object:\s+DN:\s+({object_dn}.+?)\s+GUID:""",
    """Object:\s+DN:.+?({object_ou}OU.+?)\s+GUID:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```