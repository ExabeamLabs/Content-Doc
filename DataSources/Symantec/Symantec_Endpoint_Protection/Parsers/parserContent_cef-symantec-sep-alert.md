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
    """({host}[\w.\-]{1,2000})\s{1,100}email_conviction_event:""",
    """CEF:([^\|]{0,2000}\|){5}({alert_type}[^\|]{1,2000})""",
    """"device_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """\WinternalIP=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\WinternalHost=({src_host}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmd5=({md5}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wuser_name=({user}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"threat":\{[^\}]{0,2000}?"name":"({alert_name}[^"]{1,2000})""",
    """"receivers":.*?"email_address":"({user_email}[^"]{1,2000})".*?"direction":"I"""",
    """"direction":"I".*?"receivers":.*?"email_address":"({user_email}[^"]{1,2000})"""",
    """"sender":.*?"email_address":"({additional_info}[^"]{1,2000})".*?"direction":"I"""",
    """"direction":"I".*?"sender":.*?"email_address":"({additional_info}[^"]{1,2000})"""",
    """"email_action":"({outcome}[^"]{1,2000})""",
    """"severity":({alert_severity}\d{1,100})""",
    """"file":.+?"name":"({malware_file_name}[^"]{1,2000})""",
    """"sender_ip":"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
  ]
}
```