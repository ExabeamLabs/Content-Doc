#### Parser Content
```Java
{
Name = foxt-local-logon
  Vendor = HelpSystems
  Product = Powertech Identity Access Manager (BoKs)
  Lms = Exabeam
  DataType = "local-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "login - login_ok", "Successful login" ]
  Fields = [
    """clientTime="*({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)Z"*""",
    """authHost="*({host}[^"]+)"""",
    """user="*({user}[^"]+)""""
  ]
  DupFields = [ "host->dest_host" ]
}
```