#### Parser Content
```Java
{
Name = checkpoint-connectra-vpn-login
  Vendor = Check Point
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """,cvpn_category=Session,""", """,product=Connectra,""", """,action=ip changed,""" ]
  Fields = [
    """\,(U|u)ser=({user}[^\,]+)""",
    """\s+time=({time}\d+\w+\s+\d+:\d+:\d+)""",
    """\,src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=({host}[^\s]+)"""
  ]
}
```