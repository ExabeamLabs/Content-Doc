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
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wsuser=({os_user}[^\s]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wcs6=({database_name}.+?)\s+\w+=.+?cs6Label=Database Name""",
    """\Wcs6Label=Database Name.+?cs6=({database_name}.+?)\s+\w+=""",
    """\Wcs2=({database_object}.+?)\s+\w+=.+?cs2Label=Object Name""",
    """\Wcs2Label=Object Name.+?cs2=({database_object}.+?)\s+\w+=""",
    """\Wcs3=({db_user}.+?)\s+\w+=.+?cs3Label=Object Owner""",
    """\Wcs3Label=Object Owner.+?cs3=({db_user}.+?)\s+\w+=""",
    """\Wmsg=({db_operation}\S+)""",
    """\Wcs1=({db_query}.+?)\s+(\w+=|$)""",
    """({app}Sybase)""",
  ]
  DupFields = [ "os_user->user", "db_user->account"]
}
```