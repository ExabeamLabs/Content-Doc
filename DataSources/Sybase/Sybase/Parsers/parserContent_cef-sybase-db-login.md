#### Parser Content
```Java
{
Name = cef-sybase-db-login
  Vendor = Sybase
  Product = Sybase
  Lms = ArcSight
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Sybase|ASE Audit|""", """msg=Log in""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wsuser=({os_user}[^\s]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wcs6=({database_name}.+?)\s{1,100}\w+=.+?cs6Label=Database Name""",
    """\Wcs6Label=Database Name.+?cs6=({database_name}.+?)\s{1,100}\w+=""",
    """\Wcs4=({outcome}.+?)\s{1,100}\w+=.+?cs4Label=Result""",
    """\Wcs4Label=Result.+?cs4=({outcome}.+?)\s{1,100}\w+=""",
    """({app}Sybase)""",
  ]
  DupFields = [ "os_user->user" ]
}
```