#### Parser Content
```Java
{
Name = connectra-vpn-login
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """|product=Connectra|""", """|event_type=Login|""", """|status=Success|""" ]
  Fields = [
    """\|(U|u)ser=({user_firstname}[^,@\|]+),\s*({user_lastname}[^@\|]+)@({domain}[^\s\|]+)\s*\(({user}[^\)\|]+)\)\s*(\||$)""",
    """\|user_dn=({user_ou}[^\|]+)\|""",
    """\|user_group=({realm}[^\|]+)""",
    """\|time=({time}\d+\w+\d\d\d\d \d+:\d+:\d+)""",
    """\|src=(?:({src_ip}[a-fA-F\d.:]+)|({src_host}[\w.\-]+))\|""",
    """\|office_mode_ip=({host}[a-fA-F\d.:]+)""",
    """\|Hostname=({host}[^\|]+)\|""",
    """\|User=({user}[^,]+)""", 
  ]
  DupFields = ["user->account"]
}
```