#### Parser Content
```Java
{
Name = checkpoint-connectra-failed-vpn-login
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """,cvpn_category=Session,""", """,product=Connectra,""", """,status=Failure,""", """,event_type=Login,""" ]
  Fields = [
    """\,(U|u)ser=({user}[^\,]+)""",
    """\,user_dn=({user_ou}[^\,]+)""",
    """\s+time=({time}\d+\w+\s+\d+:\d+:\d+)""",
    """\,reason=({failure_reason}[^\,]+\S)\s*\,""",
    """\,src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\,user_group=({realm}[^\,]+)""",
    """\,Hostname=({host}[^\,]+)""",
  ]
}
```