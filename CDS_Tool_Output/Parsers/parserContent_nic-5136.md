#### Parser Content
```Java
{
Name = nic-5136
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = RsaSa
  DataType = "windows-ds-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "MSWinEventLog", "5136", "A directory service object was modified" ]
  Fields = [
    """({event_name}A directory service object was modified)""",
    """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
    """"event_time":"({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """(Information|Success Audit|Audit Success)\s+({host}[^\s]+)""",
    """"ComputerName":"({host}[\w\-.]+)""",
    """({event_code}5136)""",
    """Subject:.+?Account Name:\s*({user}.+?)\s*Account Domain:\s*({domain}.+?)\s*Logon ID:\s*({logon_id}[^\s]+)""",
    """Object:.+?Class:\s*({object_class}.+?)\s*Attribute:""",
    """Attribute:.+?LDAP Display Name:\s*({attribute}.+?)\s*Syntax""",
    """Object:\s*DN:\s*({object_dn}.+?)\s*GUID:""",
    """Object:\s*DN:.+?({object_ou}OU.+?)\s*GUID:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```