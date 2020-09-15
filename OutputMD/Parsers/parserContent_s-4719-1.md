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
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)\s+({host}[\w\-.]+)\s+AUDIT_SUCCESS""",
    """({event_code}4719)""",
    """\sAccount Name:\s*({user}.+?)\s+Account Domain""",
    """\sAccount Domain:\s*({domain}[^\s]+)""",
    """\sLogon ID:\s*({logon_id}[^\s]+)""",
    """\sCategory:\s*({audit_category}.+?)\s+Subcategory:""",
    """\sSubcategory:\s*({subcategory}.+?)\s+Subcategory GUID:""",
    """\sChanges:\s*({policy}.+?)\s*(\w+:|$)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```