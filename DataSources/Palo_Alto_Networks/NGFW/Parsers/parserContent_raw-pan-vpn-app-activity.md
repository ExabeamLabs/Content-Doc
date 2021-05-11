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
    """,GLOBALPROTECT,([^,]+,){2}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z),""",
    """({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """:\d\d:\d\d\s{1,100}({host}[\w.-]+)\s""",
    """\d\d:\d\d:\d\d\s({host}[^,]+?)\s{0,100}\d{0,100},({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d),""",
    """({vpn_client}GLOBALPROTECT),"{1,20}((({domain}[^\\,]+)\\)?(({user_email}[^@,]+@[^@,]+)|({user}[^,]+)))"{1,20},""",
    """({vpn_client}GLOBALPROTECT),(?:[^,]*,){4}({action}[^,]+)?,({activity}[^,]*)(?:[^,]*,){3}((({domain}[^\\,]+)\\)?(({user_email}[^@,]+@[^@,]+)|({user}[^,]+)))?,({country}[^,]+)?,[^,]*,(|({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})),[^,]*,(|0\.0\.0\.0|({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})),""",
    """GLOBALPROTECT,([^,]*,){18}(|(?i)any|({os}[^,]*)),""",
    """GLOBALPROTECT,([^,]*,){19}("{1,20},|"{1,20}[^"]+"{1,20},)([^,]*,){3}("{1,20},|"{1,20}({additional_info}[^"]+)"{1,20},)""",
    """,(|\s{0,100}({failure_reason}[^,]+?)"{0,20}\s{0,100}),(""{1,20}|"({additional_info}[^"]+)"),({outcome}failure)""",
    """GLOBALPROTECT,([^,]*,){19}("{1,20},|"{1,20}[^"]+"{1,20},)([^,]*,){3}("{1,20},|"{1,20}[^"]+"{1,20},)({outcome}failure|success)""",
    """GLOBALPROTECT,([^,]*,){15}({src_mac}([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})""",
    """GLOBALPROTECT,([^,]*,){19}"{0,20}(|({device_type}[^=]+?))"{0,20}\s{0,100},""",
    """GLOBALPROTECT,([^,]*,){10}({src_host}[^,]+)"""
  ]

```