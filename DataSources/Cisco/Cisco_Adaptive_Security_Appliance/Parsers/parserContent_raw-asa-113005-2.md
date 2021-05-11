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
    """exabeam_time=\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({time}\w+\s\d{1,100}\s\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100})""",
    """exabeam_host=(::ffff:)?({host}[^\s]+)""",
    """\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d\s{1,100}(::ffff:)?({host}\S+)\s{0,100}:*\s{1,100}%ASA""",
    """reason\s{0,100}=\s{0,100}({failure_reason}[^:=]+?)\s{0,100}:""",
    """user\s{0,100}=\s{0,100}(?:|({user}[^:]+))\s{1,100}:""",
    """user IP\s{0,100}=\s{0,100}(::ffff:)?({src_ip}[a-fA-F\d.:]+)""",
    """%ASA-\d{1,100}-({event_code}113005)""",
    """({event_name}AAA user authentication Rejected)""",
 ]
}
```