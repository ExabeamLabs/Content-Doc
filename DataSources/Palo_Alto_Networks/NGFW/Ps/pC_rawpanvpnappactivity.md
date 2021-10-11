#### Parser Content
```Java
{
Name = raw-pan-vpn-app-activity
  DataType = "app-activity"
  Conditions = [ """,GLOBALPROTECT,"""]
  Fields = ${PaloAltoParserTemplates.raw-pan-vpn-event.Fields}[
    """,({app}GLOBALPROTECT),""",
    """GLOBALPROTECT,([^,]{0,2000}
raw-pan-vpn-event = {
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Fields = [
    """,GLOBALPROTECT,([^,]{1,2000},){2}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z),""",
    """({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """:\d\d:\d\d\s{1,100}({host}[\w.-]{1,2000})\s""",
    """\d\d:\d\d:\d\d\s({host}[^,]{1,2000}?)\s{0,100}\d{0,100},({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d),""",
    """({vpn_client}GLOBALPROTECT),"{1,20}((({domain}[^\\,]{1,2000})\\)?(({user_email}[^@,]{1,2000}@[^@,]{1,2000})|({user}[^,]{1,2000})))"{1,20},""",
    """({vpn_client}GLOBALPROTECT),(?:[^,]{0,2000},){4}({action}[^,]{1,2000})?,({activity}[^,]{0,2000})(?:[^,]{0,2000},){3}((({domain}[^\\,]{1,2000})\\)?((({user}[^@,]{1,2000})@({=domain}[^@,.]{1,2000}\.lan))|({user_email}[^@,]{1,2000}@[^@,]{1,2000})|(pre-logon|\.{3}|({=user}[^,]{1,2000}))))?,({country}[^,]{1,2000})?,[^,]{0,2000},(|({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})),[^,]{0,2000},(|0\.0\.0\.0|({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})),""",
    """GLOBALPROTECT,([^,]{0,2000},){18}(|(?i)any|({os}[^,]{0,2000})),""",
    """GLOBALPROTECT,([^,]{0,2000},){19}("{1,20},|"{1,20}[^"]{1,2000}"{1,20},)([^,]{0,2000},){3}("{1,20},|"{1,20}({additional_info}[^"]{1,2000})"{1,20},)""",
    """,(|\s{0,100}({failure_reason}[^,]{1,2000}?)\s{0,100}"{0,20}\s{0,100}),(""{1,20}|"({additional_info}[^"]{1,2000})"),({outcome}failure)""",
    """GLOBALPROTECT,([^,]{0,2000},){19}("{1,20},|"{1,20}[^"]{1,2000}"{1,20},)([^,]{0,2000},){3}("{1,20},|"{1,20}[^"]{1,2000}"{1,20},)({outcome}failure|success)""",
    """GLOBALPROTECT,([^,]{0,2000},){15}({src_mac}([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})""",
    """GLOBALPROTECT,([^,]{0,2000},){19}"{0,20}(|({device_type}[^=]{1,2000}?))"{0,20}\s{0,100},""",
    """GLOBALPROTECT,([^,]{0,2000},){10}({src_host}[^,]{1,2000})"""
  ]

```