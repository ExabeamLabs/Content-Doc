#### Parser Content
```Java
{
Name = raw-asa-113005-2
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """%ASA""" , """-113005""", """ AAA failure ""","""server =""" ]
  Fields = [
    """exabeam_time=\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\w+\s\d+\s\d+\s\d+:\d+:\d+)""",
    """exabeam_host=(::ffff:)?({host}[^\s]+)""",
    """\w+\s+\d+ \d\d:\d\d:\d\d\s+(::ffff:)?({host}\S+)\s*:*\s+%ASA""",
    """reason\s*=\s*({failure_reason}[^:=]+?)\s*:""",
    """user\s*=\s*(?:|({user}[^:]+))\s+:""",
    """user IP\s*=\s*(::ffff:)?({src_ip}[a-fA-F\d.:]+)""",
    """%ASA-\d+-({event_code}113005)""",
    """({event_name}AAA user authentication Rejected)""",
 ]
}
```