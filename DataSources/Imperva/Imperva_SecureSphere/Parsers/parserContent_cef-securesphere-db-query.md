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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """\Wdst=\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wsrc=\s{0,100}(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wproto=({protocol}[^\s]{1,2000})""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wduser="{0,20}(({domain}[^\\\s",]{1,2000})\\+)?({db_user}[^\\\s",]{1,2000})"{0,20}\s{0,100}(\w+=|$)""",
    """\Wcs2=(|({server_group}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs3=(|({service_name}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs4=(|({app}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs11="{0,20}(({domain}[^\\\s",]{1,2000})\\+)?({user}[^\\\s",]{1,2000})"{0,20}\s{0,100}(\w+=|$)""",
    """\Wcs12=(({domain}[^\\\s]{1,2000})\\+)?({host}[\w\-.]{1,2000})""",
    """\Wcs13=(|({database_name}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs14=(|({schema}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs15=\s{0,100}(|({db_query}.+?))\s{0,100}(\w+=|$)""",
    """\Wcs16=.*?({db_operation}(?i)(insert|delete|truncate|drop|alter|create|update|enable|disable|merge|delete|merge|select|dbcc))""",
    """\Wcs19=({response_size}\d{1,100})""",
  ]
  DupFields = [ "db_user->account" ]
}
```