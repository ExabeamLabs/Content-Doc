#### Parser Content
```Java
{
Name = checkpoint-connectra-vpn-logout
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """,cvpn_category=Session,""", """,product=Connectra,""", """,event_type=Logout,""" ]
  Fields = [
    """\,(U|u)ser=({user}[^\,]+)""",
    """\,user_dn=({user_ou}[^\,]+)""",
    """\s{1,100}time=({time}\d{1,100}\w+\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """\,src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\,reason=({reason}[^\,]+)""",
    """exabeam_host=({host}[^\s]+)"""
  ]
}
```