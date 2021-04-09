#### Parser Content
```Java
{
Name = raw-5136
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-ds-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "5136", "A directory service object was modified" ]
  Fields = [ 
    """({time}\d+/\d+/\d+ \d+:\d+:\d+ (am|AM|pm|PM))""",
    """({event_name}A directory service object was modified)""",
    """exabeam_host=([^=]+?@\s*)?({host}[\w.-]+)""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)[\s,]({host}[\w.-]+)""",
    """__li_source_path="*({host}[^"]+)"""",
    """<Computer>({host}[^<]+)</Computer>""",
    """Computer(Name)?\s*\\*"?(=|:|>)\s*"*({host}[\w\.-]+)(\s|,|"|</Computer>|$)""",
    """Microsoft-Windows-Security-Auditing.*?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s+(am|AM|pm|PM|({host}[\w.\-]+))""",
    """\WTimeGenerated=({time}\d+)""", 
    """({event_code}5136)""",
    """Subject:.+?Account Name:\s+(SYSTEM|({user}.+?))\s+Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """Object:.+?Class:\s+({object_class}.+?)\s+Attribute:""",
    """Attribute:.+?LDAP Display Name:\s+({attribute}.+?)\s+Syntax""",
    """Object:\s+DN:\s+({object_dn}.+?)\s+GUID:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```