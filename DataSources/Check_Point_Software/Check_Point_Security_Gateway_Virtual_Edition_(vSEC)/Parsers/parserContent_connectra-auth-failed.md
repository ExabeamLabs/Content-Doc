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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}((\+|\-)\d\d:\d\d)?)""",
    """({host}[\w.\-]+)\s{1,100}CPLogToSyslog:""",
    """\WOriginSicName:\s{0,100}CN=({host}[\w.\-]+),O="""
    """\WAction:\s{0,100}(|({action}[^;]+?));""",
    """\Wuser:\s{0,100}({user}[^;\(\)]+?)\s{0,100};""",
    """\Wuser:\s{0,100}({user_fullname}.+?)\s{0,100}\(({account}.+?)\)""",
    """\Wsrc:\s{0,100}(|({src_ip}[a-fA-F\d.:]+));""",
    """\WProductName:\s{0,100}(|({app}[^;]+?));""",
    """\Wauth_method:\s{0,100}(|({auth_method}[^;]+?));""",
    """\Wos_name:\s{0,100}(|({os}[^;]+?));""",
    """\Wstatus:\s{0,100}(|({outcome}[^;]+?));""",
    """\Wreason:\s{0,100}(|({failure_reason}[^;]+?))\s{0,100};""",
    """\Whost_ip:\s{0,100}({dest_ip}[a-fA-F\d.:]+)""",
  ]
   DupFields = [ "action->event_name", "account->user" ]
}
```