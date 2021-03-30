#### Parser Content
```Java
{
Name = raw-pan-vpn-login
  DataType = "vpn-login"
  Conditions = [ """,GLOBALPROTECT,""", """,connected,""", """,success,"""]
  Fields = ${PaloAltoParserTemplates.raw-pan-vpn-event.Fields}[
    """,({app}GLOBALPROTECT),""",
    """({outcome}success|Success|SUCCESS)""",
  ]
}
raw-pan-vpn-event = {
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Fields = [
    """({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\d\d:\d\d:\d\d\s({host}[^,]+?)\s*\d*,({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d),""",
    """({vpn_client}GLOBALPROTECT),"+((({domain}[^\\,]+)\\)?(({user_email}[^@,]+@[^@,]+)|({user}[^,]+)))"+,""",
    """({vpn_client}GLOBALPROTECT),(?:[^,]*,){4}({action}[^,]+)?,({activity}[^,]*)(?:[^,]*,){3}((({domain}[^\\,]+)\\)?(({user_email}[^@,]+@[^@,]+)|({user}[^,]+)))?,({country}[^,]+)?,[^,]*,({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),[^,]*,(0\.0\.0\.0|({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})),""",
    """GLOBALPROTECT,([^,]*,){18}((?i)any|({os}[^,]*)),""",
    """GLOBALPROTECT,([^,]*,){19}("+,|"+[^"]+"+,)([^,]*,){3}("+,|"+({additional_info}[^"]+)"+,)""",
    """,(|\s*({failure_reason}[^,]+?)"*\s*),(""+|"({additional_info}[^"]+)"),({outcome}failure)""",
    """GLOBALPROTECT,([^,]*,){19}("+,|"+[^"]+"+,)([^,]*,){3}("+,|"+[^"]+"+,)({outcome}failure|success)""",
    """GLOBALPROTECT,([^,]*,){15}({src_mac}([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})""",
    """GLOBALPROTECT,([^,]*,){19}"*(|({device_type}[^=]+?))"*\s*,"""
  ]

```