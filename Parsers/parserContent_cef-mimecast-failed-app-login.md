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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) [\w.\-]+ Skyformation""",
    """IP:\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),""",
    """\Wext_user=(|({user_email}[^@]+@[^=]+?))(\s+\w+=|\s*$)""",
    """\sReason:\s(|({failure_reason}[^=]+?))(\s+\w+=|\s*$)""",
    """\sApplication:\s*({app}[^,]+?),""",
    """"user":"({user_email}[^"]+)"""
  ]
}
```