#### Parser Content
```Java
{
Name = connectra-auth-successful
  Vendor = Check Point Software
  Product = Check Point Security Gateway Virtual Edition (vSEC)
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """ProductName: Connectra;""", """Action: authcrypt;""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}((\+|\-)\d\d:\d\d)?)""",
    """({host}[\w.\-]{1,2000})\s{1,100}CPLogToSyslog:""",
    """\WOriginSicName:\s{0,100}CN=({host}[\w.\-]{1,2000}),O="""
    """\WAction:\s{0,100}(|({action}[^;]{1,2000}?));""",
    """\Wuser:\s{0,100}({user}[^;\(\)]{1,2000}?)\s{0,100};""",
    """\Wuser:\s{0,100}({user_fullname}.+?)\s{0,100}\(({account}.+?)\)""",
    """\Wsrc:\s{0,100}(|({src_ip}[a-fA-F\d.:]{1,2000}));""",
    """\WProductName:\s{0,100}(|({app}[^;]{1,2000}?));""",
    """\Wauth_method:\s{0,100}(|({auth_method}[^;]{1,2000}?));""",
    """\Wos_name:\s{0,100}(|({os}[^;]{1,2000}?));""",
    """\Wstatus:\s{0,100}(|({outcome}[^;]{1,2000}?));""",
    """\Whost_ip:\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000})""",
  ]
   DupFields = [ "action->event_name", "account->user" ]
}
```