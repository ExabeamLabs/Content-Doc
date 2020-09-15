#### Parser Content
```Java
{
Name = connectra-auth-failed
  Vendor = Check Point Software
  Product = Check Point Security Gateway Virtual Edition (vSEC)
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """ProductName: Connectra;""", """Action: authcrypt_failed;""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+((\+|\-)\d\d:\d\d)?)""",
    """({host}[\w.\-]+)\s+CPLogToSyslog:""",
    """\WOriginSicName:\s*CN=({host}[\w.\-]+),O="""
    """\WAction:\s*(|({action}[^;]+?));""",
    """\Wuser:\s*({user}[^;\(\)]+?)\s*;""",
    """\Wuser:\s*({user_fullname}.+?)\s*\(({account}.+?)\)""",
    """\Wsrc:\s*(|({src_ip}[a-fA-F\d.:]+));""",
    """\WProductName:\s*(|({app}[^;]+?));""",
    """\Wauth_method:\s*(|({auth_method}[^;]+?));""",
    """\Wos_name:\s*(|({os}[^;]+?));""",
    """\Wstatus:\s*(|({outcome}[^;]+?));""",
    """\Wreason:\s*(|({failure_reason}[^;]+?))\s*;""",
    """\Whost_ip:\s*({dest_ip}[a-fA-F\d.:]+)""",
  ]
   DupFields = [ "action->event_name", "account->user" ]
}
```