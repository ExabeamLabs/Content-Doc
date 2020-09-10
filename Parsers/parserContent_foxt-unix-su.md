#### Parser Content
```Java
{
Name = foxt-unix-su
  Vendor = Fox BoKS ServerControl
  Lms = Exabeam
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """access.user.su""", "su_ok", "Successful SU from user" ]
  Fields = [
    """clientTime="*({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)Z"*""",
    """\d\dZ\s+({host}[\w\-.]+)\s+su - su_ok""",
    """user="*({user}[^"]+)"""",
    """touser="*({account}[^"]+)"""",
    """authHost="*({host}[^"]+)"""",
    """fromhost="*({dest_ip}[^"]+)"""",
    """({event_code}su)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```