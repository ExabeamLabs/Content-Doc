#### Parser Content
```Java
{
Name = cef-mimecast-failed-app-login
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = ArcSight
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """destinationServiceName=Mimecast Email Security""", """|cat=access """, """Logon Authentication Failed""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) [\w.\-]+ Skyformation""",
    """IP:\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),""",
    """\Wext_user=(|({user_email}[^@]+@[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sReason:\s(|({failure_reason}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sApplication:\s{0,100}({app}[^,]+?),""",
    """"user":"({user_email}[^"]+)"""
  ]
}
```