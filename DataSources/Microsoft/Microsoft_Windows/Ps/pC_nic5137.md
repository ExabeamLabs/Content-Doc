#### Parser Content
```Java
{
Name = nic-5137
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = RsaSa
  DataType = "windows-ds-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "MSWinEventLog", " 5137 Microsoft-Windows-Security-Auditing", "A directory service object was created" ]
  Fields = [
    """({event_name}A directory service object was created)""",
    """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """(Information|Success Audit|Audit Success)\s{1,100}({host}[^\s]{1,2000})""",
    """({event_code}5137)""",
    """Subject:.+?Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """Object:.+?Class:\s{1,100}({object_class}.+?)\s{1,100}Operation:""",
    """Object:\s{1,100}DN:\s{1,100}({object_dn}.+?)\s{1,100}GUID:""",
    """Object:\s{1,100}DN:.+?({object_ou}OU.+?)\s{1,100}GUID:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```