#### Parser Content
```Java
{
Name = l-ironport-dlp-email-alert
  Vendor = Cisco
  Product = IronPort Email
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ MID """, """ From=""", """To=""", """Subject=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """\WFrom=[^<]{1,2000}<({sender}[^@]{1,2000}@[^>,]{1,2000})""",
    """To=({recipient}[^=]{1,2000}?)(,\s{1,100}\w+=|\s{0,100}$)""",
    """Subject=({subject}.+?)(,\s{1,100}\w+=|\s{0,100}$)""",
    """RemoteIP=({dest_ip}[A-Fa-f.:\d]{1,2000})""",
    """MID ({alert_id}\d{1,100})"""
  ]


}
```