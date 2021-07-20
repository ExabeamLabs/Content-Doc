#### Parser Content
```Java
{
Name = connectra-vpn-end
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """|product=Connectra|""", """|event_type=Logout|""" ]
  Fields = [
    """\|(U|u)ser=({user_firstname}[^,@\|]{1,2000}),\s{0,100}({user_lastname}[^@\|]{1,2000})@({domain}[^\s\|]{1,2000})\s{0,100}\(({user}[^\)\|]{1,2000})\)""",
    """\|user_dn=({user_ou}[^\|]{1,2000})\|""",
    """\|time=({time}\d{1,100}\w+\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100})""",
    """\|src=(?:({src_ip}[a-fA-F\d.:]{1,2000})|({src_host}[\w.\-]{1,2000}))\|""",
    """\|reason=({failure_reason}[^\|]{1,2000})\|"""
  ]
}
```