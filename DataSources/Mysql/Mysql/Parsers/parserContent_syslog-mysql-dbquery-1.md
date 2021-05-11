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
      """message"{1,20}:"{1,20}[^,]*,({host}[^,]+)""",
      """message"{1,20}:"{1,20}({time}\d\d\d\d\d\d\d\d \d\d:\d\d:\d\d)""",
      """({app}mysql)""",
      """,QUERY,[^\}]+?(concat\([^\)]+\))?\s(?i)from\s{1,100}\`?({database_name}[^.,\`]+)\`?\.\`?({table_name}\w+)\`?""",
      """message"{1,20}:"{1,20}([^,]+,){2}({user}[^,]+),""",
      """message"{1,20}:"{1,20}([^,]+,){2}v(_|-)okta-(\w+-)?({user}\w+)(-|_priv_vault)""",
      """message"{1,20}:"{1,20}([^,]+,){3}({src_ip}[^,]+),""",
      """,QUERY,({database_name}[^,]+),""",
      """,QUERY,[^,]*,'(?:\/\*[^\/]+\/)?\s{0,100}({db_operation}\w+)""",
      """,QUERY,[^,]*,'(?:\/\*[^\/]+\/)?\s{0,100}({db_query}[^\}]+?)\s{0,100}',({error_code}\d{1,100})?\s{0,100}""""
    ]
    DupFields = [ "host->dest_host" ]
  }
```