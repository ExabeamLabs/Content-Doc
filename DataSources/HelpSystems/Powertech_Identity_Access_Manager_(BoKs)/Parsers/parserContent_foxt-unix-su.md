#### Parser Content
```Java
{
Name = foxt-unix-su
  Vendor = HelpSystems
  Product = Powertech Identity Access Manager (BoKs)
  Lms = Exabeam
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """access.user.su""", "su_ok", "Successful SU from user" ]
  Fields = [
    """clientTime="{0,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)Z"{0,20}""",
    """\d\dZ\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}su - su_ok""",
    """user="{0,20}({user}[^"]{1,2000})"""",
    """touser="{0,20}({account}[^"]{1,2000})"""",
    """authHost="{0,20}({host}[^"]{1,2000})"""",
    """fromhost="{0,20}({dest_ip}[^"]{1,2000})"""",
    """({event_code}su)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```