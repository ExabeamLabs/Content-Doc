#### Parser Content
```Java
{
Name = cisco-esa-dlp-alert-1
  Vendor = Cisco
  Product = Cisco Secure Email
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF""" , """ Email Security Appliance|""", """ ESAMID=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """suser=({sender}[^\s]+)""",
    """\sduser=({recipients}[^\s]+)\s{1,100}(\w+=|$)""",
    """\sduser=({recipient}[^,\s;]+)""",
    """sourceAddress=({src_ip}[A-Fa-f:\d.]+)""",
    """ESAMID=({alert_id}\d{1,100})""",
    """\|Cisco\|([^\|]*\|){2}({alert_type}[^\|]+)""",
    """\|Cisco\|([^\|]*\|){3}({alert_name}[^\|]+)""",
    """\|Cisco\|([^\|]*\|){4}({alert_severity}[^\|]+)"""
    """deviceDirection=({direction}\d)""",
    """\Wact=({action}[^=]+?)\s{0,100}\w+="""
  ]
  DupFields = [ "sender->user_email", "action->outcome" ]
}
```