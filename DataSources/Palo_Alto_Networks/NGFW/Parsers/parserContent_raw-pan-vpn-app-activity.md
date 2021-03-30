#### Parser Content
```Java
{
Name = raw-pan-vpn-app-activity
  DataType = "app-activity"
  Conditions = [ """,GLOBALPROTECT,"""]
  Fields = ${PaloAltoParserTemplates.raw-pan-vpn-event.Fields}[
    """,({app}GLOBALPROTECT),""",
  ]
}
raw-pan-vpn-event = {
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Fields = [
    """\d\d:\d\d:\d\d\s({host}[^,]+?)\s*\d*,({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d),""",
    """({vpn_client}GLOBALPROTECT),.*?,\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d,.*?,({action}[^,]+),({activity}[^,]+),.*?,.*?,((({domain}[^\\]+)\\)?({user}[^,]+))?,({country}[^,]+)?,.*?,({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),.*?,({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """({failure_reason}[^,]+)?,(""|"({additional_info}[^"]+)"),({outcome}failure|success)"""
  ]

```