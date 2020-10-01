#### Parser Content
```Java
{
Name = cef-securesphere-db-query
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = ArcSight
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Imperva Inc.|SecureSphere|""", """cs6=Query""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """\Wdst=\s*({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wsrc=\s*(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\Wspt=({src_port}\d+)""",
    """\Wproto=({protocol}[^\s]+)""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wduser="*(({domain}[^\\\s",]+)\\+)?({db_user}[^\\\s",]+)"*\s*(\w+=|$)""",
    """\Wcs2=(|({server_group}.+?))\s*(\w+=|$)""",
    """\Wcs3=(|({service_name}.+?))\s*(\w+=|$)""",
    """\Wcs4=(|({app}.+?))\s*(\w+=|$)""",
    """\Wcs11="*(({domain}[^\\\s",]+)\\+)?({user}[^\\\s",]+)"*\s*(\w+=|$)""",
    """\Wcs12=(({domain}[^\\\s]+)\\+)?({host}[\w\-.]+)""",
    """\Wcs13=(|({database_name}.+?))\s*(\w+=|$)""",
    """\Wcs14=(|({schema}.+?))\s*(\w+=|$)""",
    """\Wcs15=\s*(|({db_query}.+?))\s*(\w+=|$)""",
    """\Wcs16=.*?({db_operation}(?i)(insert|delete|truncate|drop|alter|create|update|enable|disable|merge|delete|merge|select|dbcc))""",
    """\Wcs19=({response_size}\d+)""",
  ]
  DupFields = [ "db_user->account" ]
}
```