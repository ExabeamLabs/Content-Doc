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
    """clientTime="{0,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)Z"{0,20}""",
    """authHost="{0,20}({host}[^"]{1,2000})"""",
    """user="{0,20}({user}[^"]{1,2000})""""
  ]
  DupFields = [ "host->dest_host" ]
}
```