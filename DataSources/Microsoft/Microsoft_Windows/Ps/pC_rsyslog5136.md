#### Parser Content
```Java
{
Name = r-syslog-5136
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-ds-access"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ ",5136,", "A directory service object was modified" ]
  Fields = [
    """({event_name}A directory service object was modified)""",
    """({time}\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """(Information|Success Audit|Audit Success),({host}[^,]{1,2000})""",
    """({event_code}5136)""",
    """Subject:.+?Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """Object:.+?Class:\s{1,100}({object_class}.+?)\s{1,100}Attribute:""",
    """Attribute:.+?LDAP Display Name:\s{1,100}({attribute}.+?)\s{1,100}Syntax""",
    """Object:\s{1,100}DN:\s{1,100}({object_dn}.+?)\s{1,100}GUID:""",
    """Object:\s{1,100}DN:.+?({object_ou}OU.+?)\s{1,100}GUID:"""
  ]
  DupFields = [ "host->dest_host" ]


}
```