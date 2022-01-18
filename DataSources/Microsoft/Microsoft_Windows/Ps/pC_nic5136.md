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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """(Information|Success Audit|Audit Success)\s{1,100}({host}[^\s]{1,2000})""",
    """"ComputerName":"({host}[\w\-.]{1,2000})""",
    """({event_code}5136)""",
    """Subject:.+?Account Name:\s{0,100}({user}.+?)\s{0,100}Account Domain:\s{0,100}({domain}.+?)\s{0,100}Logon ID:\s{0,100}({logon_id}[^\s]{1,2000})""",
    """Object:.+?Class:\s{0,100}({object_class}.+?)\s{0,100}Attribute:""",
    """Attribute:.+?LDAP Display Name:\s{0,100}({attribute}.+?)\s{0,100}Syntax""",
    """Object:\s{0,100}DN:\s{0,100}({object_dn}.+?)\s{0,100}GUID:""",
    """Object:\s{0,100}DN:.+?({object_ou}OU.+?)\s{0,100}GUID:"""
  ]
  DupFields = [ "host->dest_host" ]


}
```