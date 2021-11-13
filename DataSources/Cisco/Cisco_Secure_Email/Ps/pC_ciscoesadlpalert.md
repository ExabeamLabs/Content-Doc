#### Parser Content
```Java
{
Name = cisco-esa-dlp-alert
  Vendor = Cisco
  Product = Cisco Secure Email
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF""" , """Email Security Virtual Appliance""", """suser=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """suser=({sender}[^\s]{1,2000})""",
    """\sduser=({recipients}[^\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\sduser=({recipient}[^,\s;]{1,2000})""",
    """sourceAddress=({src_ip}[^\s]{1,2000})""",
    """msg='({subject}[^']{1,2000})'""",
    """ESAMID=({alert_id}\d{1,100})""",
    """cfp1=(not enabled|({alert_severity}[^\s]{1,2000}))""",
    """\|Cisco\|([^\|]{0,2000}\|){2}({alert_type}[^\|]{1,2000})""",
    """\|Cisco\|([^\|]{0,2000}\|){3}({alert_name}[^\|]{1,2000})""",
    """\|Cisco\|([^\|]{0,2000}\|){4}({alert_severity}[^\|]{1,2000})"""
    """deviceDirection=({direction}\d)""",
  ]
  DupFields = [ "sender->user_email" ]


}
```