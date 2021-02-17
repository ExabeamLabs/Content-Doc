#### Parser Content
```Java
{
Name = nic-5141
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = RsaSa
  DataType = "windows-ds-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "MSWinEventLog", " 5141 Microsoft-Windows-Security-Auditing", "A directory service object was deleted" ]
  Fields = [
    """({event_name}A directory service object was deleted)""",
    """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
    """exabeam_host=({host}[\w.\-]+)""",
    """(Information|Success Audit|Audit Success)\s+({host}[^\s]+)""",
    """({event_code}5141)""",
    """Subject:.+?Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """Object:.+?Class:\s+({object_class}.+?)\s+Operation:""",
    """Object:\s+DN:\s+({object_dn}.+?)\s+GUID:""",
    """Object:\s+DN:.+?({object_ou}OU.+?)\s+GUID:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```