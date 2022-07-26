#### Parser Content
```Java
{
Name = raw-asa-113005
  Vendor = Cisco
  Product = Adaptive Security Appliance
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """%ASA""" , """-113005""", """ AAA user """ ]
  Fields = [
    """exabeam_host=(::ffff:)?({host}[^\s]{1,2000})""",
    """exabeam_time=\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d\s{1,100}(::ffff:)?({host}\S+)\s{0,100}:*\s{1,100}%ASA""",
    """\s({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """reason\s{0,100}=\s{0,100}({failure_reason}[^;=]{1,2000}?)\s{0,100}:""",
    """server\s{0,100}=\s{0,100}(::ffff:)?({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """user\s{0,100}=\s{0,100}(({user_email}[^@\s":]{1,2000}@[^@\s":]{1,2000})|((\*{1,100}?)|({user}[^@:\s"]{1,2000})@({domain}[^:\.@"\s]{1,2000})|(({=domain}[^\\\/:\s"]{1,2000})[\\\/]{1,20})?({=user}[^"\s:]{1,2000})))\s{1,100}:""",
    """user IP\s{0,100}=\s{0,100}(::ffff:)?({src_ip}[a-fA-F\d.:]{1,2000})""",
    """%ASA-\d{1,100}-({event_code}113005)""",
    """({event_name}AAA user (authentication|authorization) Rejected)""",
 ]


}
```