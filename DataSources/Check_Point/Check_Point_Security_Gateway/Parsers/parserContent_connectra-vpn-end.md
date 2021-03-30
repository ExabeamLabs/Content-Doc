#### Parser Content
```Java
{
Name = connectra-vpn-end
  Vendor = Check Point
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """|product=Connectra|""", """|event_type=Logout|""" ]
  Fields = [
    """\|(U|u)ser=({user_firstname}[^,@\|]+),\s*({user_lastname}[^@\|]+)@({domain}[^\s\|]+)\s*\(({user}[^\)\|]+)\)""",
    """\|user_dn=({user_ou}[^\|]+)\|""",
    """\|time=({time}\d+\w+\d\d\d\d \d+:\d+:\d+)""",
    """\|src=(?:({src_ip}[a-fA-F\d.:]+)|({src_host}[\w.\-]+))\|""",
    """\|reason=({failure_reason}[^\|]+)\|"""
  ]
}
```