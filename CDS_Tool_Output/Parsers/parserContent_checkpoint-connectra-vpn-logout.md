#### Parser Content
```Java
{
Name = checkpoint-connectra-vpn-logout
  Vendor = Check Point
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """,cvpn_category=Session,""", """,product=Connectra,""", """,event_type=Logout,""" ]
  Fields = [
    """\,(U|u)ser=({user}[^\,]+)""",
    """\,user_dn=({user_ou}[^\,]+)""",
    """\s+time=({time}\d+\w+\s+\d+:\d+:\d+)""",
    """\,src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\,reason=({reason}[^\,]+)""",
    """exabeam_host=({host}[^\s]+)"""
  ]
}
```