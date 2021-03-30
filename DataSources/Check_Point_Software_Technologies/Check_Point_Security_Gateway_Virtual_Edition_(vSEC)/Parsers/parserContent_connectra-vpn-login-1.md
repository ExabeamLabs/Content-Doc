#### Parser Content
```Java
{
Name = connectra-vpn-login-1
  Vendor = Check Point Software Technologies
  Product = Check Point Security Gateway Virtual Edition (vSEC)
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """ProductName: Connectra;""", """ip changed""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+((\+|\-)\d\d:\d\d)?)""",
    """({host}[\w.\-]+)\s+CPLogToSyslog:""",
    """\WOriginSicName:\s*CN=({host}[\w.\-]+),O="""
    """\WAction:\s*(|({action}[^;]+?));""",
    """\Wuser:\s*({user}[^;\(\)]+?)\s*;""",
    """\Wuser:\s*({user_fullname}.+?)\s*\(({account}.+?)\)""",
    """\Wsrc:\s*(|({src_ip}[a-fA-F\d.:]+));""",
    """\WProductName:\s*(|({app}[^;]+?));""",
    """\Wassigned_IP::\s*({dest_ip}[a-fA-F\d.:]+)""",
    """\,orig=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
   DupFields = [ "action->event_name", "account->user" ]
}
```