#### Parser Content
```Java
{
Name = q-microsoft-4719
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-audit"
  TimeFormat = "epoch_sec"
  Conditions = [ "EventIDCode=4719", "System audit policy was changed" ]
  Fields = [
    """({event_name}System audit policy was changed)""",
    """TimeGenerated=({time}\d{1,100})""",
    """EventIDCode=({event_code}\d{1,100})""",
    """\s{1,100}Account Name:\s{1,100}(({domain}[^\\]{1,2000})\\+)?({user}[^\s\\]{1,2000})\s{1,100}Account Domain""",
    """\s{1,100}Account Domain:\s{1,100}({domain}[^\s]{1,2000})""",
    """\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """\s{1,100}Category:\s{1,100}({audit_category}.+?)\s{1,100}Subcategory:""",
    """\s{1,100}Subcategory:\s{1,100}({subcategory}.+?)\s{1,100}Subcategory GUID:""",
    """\s{1,100}Changes:\s{1,100}({policy}.+?)\s{0,100}(\w+:|$)""",
    """\s{1,100}Computer=({host}[\w.\-]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]
}
```