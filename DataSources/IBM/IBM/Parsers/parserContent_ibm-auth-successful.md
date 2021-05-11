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
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}).*?ind--bindDN""",
    """uid=({user}[^\s,=]+)""",
    """client:\s{0,100}((:0|::1|({src_ip}[A-Fa-f:\d.]+?))(:({src_port}\d{1,100}))?)\-*connectionID:""",
  ]
}
```