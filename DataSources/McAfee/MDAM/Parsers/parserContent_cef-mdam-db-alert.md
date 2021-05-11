#### Parser Content
```Java
{
Name = cef-mdam-db-alert
  Vendor = McAfee
  Product = MDAM
  Lms = ArcSight
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|McAfee|DAM|""", """|alert|""", """externalId=""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wcs1=MSSQL:({host}[\w\-.]+)""",
    """\WexternalId=({alert_id}\d{1,100})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wduser=((|NT AUTHORITY|({domain}[^\\\s]+))\\+)?(|SYSTEM|({user}[^\\\s]+))\s{1,100}(\w+=|$)""",
    """\Wsuser=((|NT AUTHORITY|({domain}[^\\\s]+))\\+)?(|SYSTEM|({user}[^\\\s]+))\s{1,100}(\w+=|$)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wact=({alert_type}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs2=\s{0,100}({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\|alert\|({alert_name}[^\|]+)""",
  ]
}
```