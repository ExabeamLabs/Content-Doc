#### Parser Content
```Java
{
Name = cef-mimecast-failed-app-login
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = ArcSight
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """destinationServiceName =Mimecast Email Security""", """Logon Authentication Failed""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) [\w.\-]{1,2000} Skyformation""",
    """IP:\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}),""",
    """"user":"(|({user_email}[^@]{1,2000}@[^"]{1,2000}?))"""",
    """\sReason:\s(|({failure_reason}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sApplication:\s{0,100}({app}[^,]{1,2000}?),""",
    """"user":"({user_email}[^"]{1,2000})"""
  ]


}
```