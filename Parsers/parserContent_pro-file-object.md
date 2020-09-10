#### Parser Content
```Java
{
Name = pro-file-object
  Vendor = Procad
  Product = Pro.File DMS
  Lms = Splunk
  DataType = "object-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [""""pdmobjectsubtypename":"""" , """"pdmobjecttypename":""""]
  Fields = [
     """autodatetime":"({time}[^"]+)""",
     """pdmobjecttypename":"({resource}[^"]+)""",
     """pdmusername":"({user}[^"]+)""",
     """pdmserverlocation":"({host}[^"]+)""",
     """pdmobjectsubtypename":"({object}[^"]+)""",
     """pdmobjectactionname":"({activity}[^"]+)"""
  ]
  DupFields = ["host->dest_host"]
}

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
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wsuser=({os_user}[^\s]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wcs6=({database_name}.+?)\s+\w+=.+?cs6Label=Database Name""",
    """\Wcs6Label=Database Name.+?cs6=({database_name}.+?)\s+\w+=""",
    """\Wcs4=({outcome}.+?)\s+\w+=.+?cs4Label=Result""",
    """\Wcs4Label=Result.+?cs4=({outcome}.+?)\s+\w+=""",
    """({app}Sybase)""",
  ]
  DupFields = [ "os_user->user" ]
}
```