#### Parser Content
```Java
{
Name = raw-5141
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "ds-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """A directory service object was deleted""", """Account Name:""" ]
  Fields = [
    """({event_name}A directory service object was deleted)""",
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s+""",
    """({event_code}5141)""",
    """(?i)(success|failure|audit)\s+\w+\s+({host}[\w\-.]+)""",
    """Subject:.+?Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """Object:.+?Class:\s+({object_class}.+?)\s+Operation:""",
    """Object:\s+DN:\s+({object_dn}.+?)\s+GUID:""",
    """Object:\s+DN:.+?({object_ou}OU.+?)\s+GUID:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```