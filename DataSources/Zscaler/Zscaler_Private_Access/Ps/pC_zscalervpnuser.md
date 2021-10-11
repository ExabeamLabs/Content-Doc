#### Parser Content
```Java
{
Name = zscaler-vpn-user
  Vendor = Zscaler
  Product = Zscaler Private Access
  Lms = Direct
  DataType = "vpn-user"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """ User Activity zpa-lss:""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\w+ ({time}\w+\s{1,100}\d{1,100} \d\d:\d\d:\d\d \d\d\d\d) User Activity zpa-lss:([^,]{0,2000},){2}({session_id}[^,]{1,2000}),({connection_id}[^,]{1,2000}),([^,]{0,2000},){2}({connection_status}[^,]{1,2000}),({protocol}[^,]{1,2000}),[^,]{0,2000},(({user_email}[^\s,@]{1,2000}@[^\s,@]{1,2000})|((({domain}[^@,]{1,2000})@)?({user}[^\s,@]{1,2000}))|({user_fullname}[^,]{1,2000})),({src_port}\d{1,100}),({src_ip}[A-Fa-f:\d.]{1,2000}),"""
  ]
}
```