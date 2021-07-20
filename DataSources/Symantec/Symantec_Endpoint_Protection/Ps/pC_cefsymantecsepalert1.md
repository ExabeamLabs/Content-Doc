#### Parser Content
```Java
{
Name = cef-symantec-sep-alert-1
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Symantec|""", """|lcp_sep_risk_event|""" ]
  Fields = [
    """({host}[\w.\-]{1,2000})\s{1,100}lcp_sep_risk_event:""",
    """CEF:([^\|]{0,2000}\|){5}({alert_type}[^\|]{1,2000})""",
    """"device_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """\WinternalIP=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\WinternalHost=({src_host}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmd5=({md5}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wuser_name=({user}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdomain_name=({domain}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"app_name":"({process}({directory}[^"]{0,2000}?)({process_name}[^"\\\/]{1,2000}))"""",
    """"event_desc":"({additional_info}[^"]{1,2000})""",
    """"severity":({alert_severity}\d{1,100})""",
    """"signature_name":"({alert_name}[^"]{1,2000})""",
  ]
}
```