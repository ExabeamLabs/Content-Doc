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
    """({host}[\w.\-]+)\s{1,100}lcp_sep_risk_event:""",
    """CEF:([^\|]*\|){5}({alert_type}[^\|]+)""",
    """"device_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """\WinternalIP=({src_ip}[a-fA-F\d.:]+)""",
    """\WinternalHost=({src_host}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmd5=({md5}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wuser_name=({user}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdomain_name=({domain}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"app_name":"({process}({directory}[^"]*?)({process_name}[^"\\\/]+))"""",
    """"event_desc":"({additional_info}[^"]+)""",
    """"severity":({alert_severity}\d{1,100})""",
    """"signature_name":"({alert_name}[^"]+)""",
  ]
}
```