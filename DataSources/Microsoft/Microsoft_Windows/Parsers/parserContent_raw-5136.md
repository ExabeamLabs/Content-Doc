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
    """({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """({event_name}A directory service object was modified)""",
    """exabeam_host=([^=]+?@\s{0,100})?({host}[\w.-]+)""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)[\s,]({host}[\w.-]+)""",
    """__li_source_path="{0,20}({host}[^"]+)"""",
    """<Computer>({host}[^<]+)</Computer>""",
    """Computer(Name)?\s{0,100}\\*"?(=|:|>)\s{0,100}"{0,20}({host}[\w\.-]+)(\s|,|"|</Computer>|$)""",
    """Microsoft-Windows-Security-Auditing.*?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s{1,100}(am|AM|pm|PM|({host}[\w.\-]+))""",
    """\WTimeGenerated=({time}\d{1,100})""", 
    """({event_code}5136)""",
    """Subject:.+?Account Name:\s{1,100}(SYSTEM|({user}.+?))\s{1,100}Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]+)""",
    """Object:.+?Class:\s{1,100}({object_class}.+?)\s{1,100}Attribute:""",
    """Attribute:.+?LDAP Display Name:\s{1,100}({attribute}.+?)\s{1,100}Syntax""",
    """Object:\s{1,100}DN:\s{1,100}({object_dn}.+?)\s{1,100}GUID:"""
  ]
  DupFields = [ "host->dest_host" ]
}
```