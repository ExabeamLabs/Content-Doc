#### Parser Content
```Java
{
Name = ibm-auth-successful
  Vendor = IBM
  Product = IBM
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ind--bindDN""", """--Success""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+).*?ind--bindDN""",
    """uid=({user}[^\s,=]+)""",
    """client:\s*((:0|::1|({src_ip}[A-Fa-f:\d.]+?))(:({src_port}\d+))?)\-*connectionID:""",
  ]
}
```