#### Parser Content
```Java
{
Name = checkpoint-connectra-vpn-login
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """,cvpn_category=Session,""", """,product=Connectra,""", """,action=ip changed,""" ]
  Fields = [
    """\,(U|u)ser=({user}[^\,]{1,2000})""",
    """\s{1,100}time=({time}\d{1,100}\w+\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """\,src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\,assigned_IP:=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\,orig=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]


}
```