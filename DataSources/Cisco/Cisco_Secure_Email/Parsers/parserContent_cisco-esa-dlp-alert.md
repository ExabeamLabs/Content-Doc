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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """suser=({sender}[^\s]+)""",
    """\ssourceHostName=({external_domain_sender}[^\s]+)""",
    """\sduser=({recipients}[^\s]+)\s{1,100}(\w+=|$)""",
    """\sduser=({recipient}[^,\s;]+)""",
    """sourceAddress=({src_ip}[^\s]+)""",
    """msg='({subject}[^']+)'""",
    """ESAMID=({alert_id}\d{1,100})""",
    """cfp1=(not enabled|({alert_severity}[^\s]+))""",
    """\|Cisco\|([^\|]*\|){2}({alert_type}[^\|]+)""",
    """\|Cisco\|([^\|]*\|){3}({alert_name}[^\|]+)""",
    """\|Cisco\|([^\|]*\|){4}({alert_severity}[^\|]+)"""
    """deviceDirection=({direction}\d)""",
  ]
  DupFields = [ "sender->user_email" ]
}
```