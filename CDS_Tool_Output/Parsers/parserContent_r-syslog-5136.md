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
    """exabeam_host=({host}[\w.\-]+)""",
    """(Information|Success Audit|Audit Success),({host}[^,]+)""",
    """({event_code}5136)""",
    """Subject:.+?Account Name:\s+({user}.+?)\s+Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """Object:.+?Class:\s+({object_class}.+?)\s+Attribute:""",
    """Attribute:.+?LDAP Display Name:\s+({attribute}.+?)\s+Syntax""",
    """Object:\s+DN:\s+({object_dn}.+?)\s+GUID:""",
    """Object:\s+DN:.+?({object_ou}OU.+?)\s+GUID:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```