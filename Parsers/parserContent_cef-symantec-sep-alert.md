#### Parser Content
```Java
{
Name = cef-symantec-sep-alert
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Symantec|""", """|email_conviction_event|""" ]
  Fields = [
    """({host}[\w.\-]+)\s+email_conviction_event:""",
    """CEF:([^\|]*\|){5}({alert_type}[^\|]+)""",
    """"device_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """\WinternalIP=({src_ip}[a-fA-F\d.:]+)""",
    """\WinternalHost=({src_host}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wmd5=({md5}[^=]+?)(\s+\w+=|\s*$)""",
    """\Wuser_name=({user}[^=]+?)(\s+\w+=|\s*$)""",
    """"threat":\{[^\}]*?"name":"({alert_name}[^"]+)""",
    """"receivers":.*?"email_address":"({user_email}[^"]+)".*?"direction":"I"""",
    """"direction":"I".*?"receivers":.*?"email_address":"({user_email}[^"]+)"""",
    """"sender":.*?"email_address":"({additional_info}[^"]+)".*?"direction":"I"""",
    """"direction":"I".*?"sender":.*?"email_address":"({additional_info}[^"]+)"""",
    """"email_action":"({outcome}[^"]+)""",
    """"severity":({alert_severity}\d+)""",
    """"file":.+?"name":"({malware_file_name}[^"]+)""",
    """"sender_ip":"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
  ]
}
```