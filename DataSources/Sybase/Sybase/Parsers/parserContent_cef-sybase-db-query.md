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
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wsuser=({os_user}[^\s]{1,2000})""",
    """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
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