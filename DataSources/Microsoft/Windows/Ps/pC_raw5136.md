#### Parser Content
```Java
{
Name = raw-5136
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  DataType = "windows-ds-access"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ "5136", "A directory service object was modified" ]
  Fields = [ 
    """({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
    """({event_name}A directory service object was modified)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?(gcs-topic|({host}[\w.-]{1,2000}))""",
    """"agent_hostname":"({host}[^"]{1,200})"""",
    """"computer":"({host}[^"]{1,200})"""",
    """(?i)(((audit|success|failure)( |_)(success|audit|failure))|information)[\s,]({host}[\w.-]{1,2000})""",
    """__li_source_path="{0,20}({host}[^"]{1,2000})"""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """Computer(Name)?\s{0,100}\\*"?(=|:|>)\s{0,100}"{0,20}({host}[\w\.-]{1,2000})(\s|,|"|</Computer>|$)""",
    """Microsoft-Windows-Security-Auditing.*?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s{1,100}(am|AM|pm|PM|({host}[\w.\-]{1,2000}))""",
    """\WTimeGenerated=({time}\d{1,100})""", 
    """({event_code}5136)""",
    """Subject:.+?Account Name:\s{1,100}(SYSTEM|({user}.+?))\s{1,100}Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """Object:.+?Class:\s{1,100}({object_class}.+?)\s{1,100}Attribute:""",
    """Attribute:.+?LDAP Display Name:\s{1,100}({attribute}.+?)\s{1,100}Syntax""",
    """Object:\s{1,100}DN:\s{1,100}({object_dn}.+?)\s{1,100}GUID:"""
  ]
  DupFields = [ "host->dest_host" ]


}
```