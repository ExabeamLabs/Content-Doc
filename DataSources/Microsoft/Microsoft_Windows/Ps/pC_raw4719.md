#### Parser Content
```Java
{
Name = raw-4719
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-audit"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "4719", "System audit policy was changed" ]
  Fields = [
    """EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """({event_name}System audit policy was changed)""",
    """({host}[^\s=]{1,2000})\sMSWinEventLog""",
    """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
    """({event_code}4719)""",
    """\s{1,100}Account Name:\s{1,100}({user}[^:]{1,2000}?)\s{1,100}Account Domain""",
    """\s{1,100}Account Domain:\s{1,100}({domain}[^\s]{1,2000})""",
    """\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """\s{1,100}Category:\s{1,100}({audit_category}.+?)\s{1,100}Subcategory:""",
    """\s{1,100}Subcategory:\s{1,100}({subcategory}.+?)\s{1,100}Subcategory GUID:""",
    """\s{1,100}Changes:\s{1,100}({policy}.*?)\s{0,100}(\||\d|<|",)"""
  ]
  DupFields = [ "host->dest_host" ]


}
```