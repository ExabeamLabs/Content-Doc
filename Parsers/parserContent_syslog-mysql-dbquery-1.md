#### Parser Content
```Java
{
Name = syslog-mysql-dbquery-1
    Vendor = Mysql
  Product = Mysql
    Lms = Direct
    DataType = "database-query"
    IsHVF = true
    TimeFormat = "yyyyMMdd HH:mm:ss"
    Conditions = [ """,QUERY,""", """CEF:""", """|SkyFormation Cloud Apps Security|""", """"ttam_category":"database/mysql"""" ]
    Fields = [
      """message"+:"+[^,]*,({host}[^,]+)""",
      """message"+:"+({time}\d\d\d\d\d\d\d\d \d\d:\d\d:\d\d)""",
      """({app}mysql)""",
      """,QUERY,.+?(concat\(.+\))?\s(from|FROM)\s+({database_name}[^.]+)\.({table_name}[^\s]+)""",
      """message"+:"+([^,]+,){2}({user}[^,]+),""",
      """message"+:"+([^,]+,){3}({src_ip}[^,]+),""",
      """,QUERY,({database_schema}[^,]+),""",
      """,QUERY,[^,]*,'\s*({db_operation}\S+)""",
      """,QUERY,[^,]*,'\s*({db_query}.+?)\s*',({error_code}\d+)?\s*""""
    ]
    DupFields = [ "host->dest_host" ]
  }
```