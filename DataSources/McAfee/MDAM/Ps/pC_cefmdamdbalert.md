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
    """\Wcs1=MSSQL:({host}[\w\-.]{1,2000})""",
    """\WexternalId=({alert_id}\d{1,100})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wduser=((|NT AUTHORITY|({domain}[^\\\s]{1,2000}))\\+)?(|SYSTEM|({user}[^\\\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """\Wsuser=((|NT AUTHORITY|({domain}[^\\\s]{1,2000}))\\+)?(|SYSTEM|({user}[^\\\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """\Wshost=({src_host}[\w\-.]{1,2000})""",
    """\Wact=({alert_type}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs2=\s{0,100}({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\|alert\|({alert_name}[^\|]{1,2000})""",
  ]
}
```