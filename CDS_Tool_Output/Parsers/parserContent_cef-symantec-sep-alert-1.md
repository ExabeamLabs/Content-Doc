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
    """({host}[\w.\-]+)\s+lcp_sep_risk_event:""",
    """CEF:([^\|]*\|){5}({alert_type}[^\|]+)""",
    """"device_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """\WinternalIP=({src_ip}[a-fA-F\d.:]+)""",
    """\WinternalHost=({src_host}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wmd5=({md5}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wuser_name=({user}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wdomain_name=({domain}[^=]+?)(\s+\w+=|\s*$)""",
    """"app_name":"({process}({directory}[^"]*?)({process_name}[^"\\\/]+))"""",
    """"event_desc":"({additional_info}[^"]+)""",
    """"severity":({alert_severity}\d+)""",
    """"signature_name":"({alert_name}[^"]+)""",
  ]
}
```