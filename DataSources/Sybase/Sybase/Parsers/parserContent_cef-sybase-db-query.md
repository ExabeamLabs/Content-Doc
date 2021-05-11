#### Parser Content
```Java
{
Name = cef-sybase-db-query
  Vendor = Sybase
  Product = Sybase
  Lms = ArcSight
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Sybase|ASE Audit|""", """msg=Select table""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wsuser=({os_user}[^\s]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wcs6=({database_name}.+?)\s{1,100}\w+=.+?cs6Label=Database Name""",
    """\Wcs6Label=Database Name.+?cs6=({database_name}.+?)\s{1,100}\w+=""",
    """\Wcs2=({database_object}.+?)\s{1,100}\w+=.+?cs2Label=Object Name""",
    """\Wcs2Label=Object Name.+?cs2=({database_object}.+?)\s{1,100}\w+=""",
    """\Wcs3=({db_user}.+?)\s{1,100}\w+=.+?cs3Label=Object Owner""",
    """\Wcs3Label=Object Owner.+?cs3=({db_user}.+?)\s{1,100}\w+=""",
    """\Wmsg=({db_operation}\S+)""",
    """\Wcs1=({db_query}.+?)\s{1,100}(\w+=|$)""",
    """({app}Sybase)""",
  ]
  DupFields = [ "os_user->user", "db_user->account"]
}
```