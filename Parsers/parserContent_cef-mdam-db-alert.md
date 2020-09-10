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
    """\Wrt=({time}\d+)""",
    """\Wcs1=MSSQL:({host}[\w\-.]+)""",
    """\WexternalId=({alert_id}\d+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wduser=((|NT AUTHORITY|({domain}[^\\\s]+))\\+)?(|SYSTEM|({user}[^\\\s]+))\s+(\w+=|$)""",
    """\Wsuser=((|NT AUTHORITY|({domain}[^\\\s]+))\\+)?(|SYSTEM|({user}[^\\\s]+))\s+(\w+=|$)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wact=({alert_type}.+?)\s+(\w+=|$)""",
    """\Wcs2=\s*({additional_info}.+?)\s+(\w+=|$)""",
    """\|alert\|({alert_name}[^\|]+)""",
  ]
}
```