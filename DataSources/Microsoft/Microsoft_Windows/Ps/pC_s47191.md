#### Parser Content
```Java
{
Name = s-4719-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-audit"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ " 4719 ", "System audit policy was changed", "AUDIT_SUCCESS" ]
  Fields = [
    """({event_name}System audit policy was changed)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}AUDIT_SUCCESS""",
    """({event_code}4719)""",
    """\sAccount Name:\s{0,100}({user}.+?)\s{1,100}Account Domain""",
    """\sAccount Domain:\s{0,100}({domain}[^\s]{1,2000})""",
    """\sLogon ID:\s{0,100}({logon_id}[^\s]{1,2000})""",
    """\sCategory:\s{0,100}({audit_category}.+?)\s{1,100}Subcategory:""",
    """\sSubcategory:\s{0,100}({subcategory}.+?)\s{1,100}Subcategory GUID:""",
    """\sChanges:\s{0,100}({policy}.+?)\s{0,100}(\w+:|$)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```