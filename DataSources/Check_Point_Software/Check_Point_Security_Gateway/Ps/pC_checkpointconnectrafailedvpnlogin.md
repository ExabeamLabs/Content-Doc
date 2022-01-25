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
    """\,(U|u)ser=({user}[^\,]{1,2000})""",
    """\,user_dn=({user_ou}[^\,]{1,2000})""",
    """\s{1,100}time=({time}\d{1,100}\w+\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """\,reason=({failure_reason}[^\,]{1,2000}\S)\s{0,100}\,""",
    """\,src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\,user_group=({realm}[^\,]{1,2000})""",
    """\,Hostname=({host}[^\,]{1,2000})""",
  ]


}
```