#### Parser Content
```Java
{
Name = f5-vpn-cert-user
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-user"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """session.ssl.cert.subject""", """01490113:5:""" ]
  Fields = [
    """(\s|")({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d)\s({host}[\w\-.]{1,2000})\s""",
    """:({session_id}[^:]{1,2000}):\ssession.ssl.cert.subject""",
    """CN=({user}[\w\-.]{1,2000})"""
  ]


}
```