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
      """message"{1,20}:"{1,20}[^,]{0,2000},({host}[^,]{1,2000})""",
      """message"{1,20}:"{1,20}({time}\d\d\d\d\d\d\d\d \d\d:\d\d:\d\d)""",
      """({app}mysql)""",
      """,QUERY,[^\}]{1,2000}?(concat\([^\)]{1,2000}\))?\s(?i)from\s{1,100}\`?({database_name}[^.,\`]{1,2000})\`?\.\`?({table_name}\w+)\`?""",
      """message"{1,20}:"{1,20}([^,]{1,2000},){2}({user}[^,]{1,2000}),""",
      """message"{1,20}:"{1,20}([^,]{1,2000},){2}v(_|-)okta-(\w+-)?({user}\w+)(-|_priv_vault)""",
      """message"{1,20}:"{1,20}([^,]{1,2000},){3}({src_ip}[^,]{1,2000}),""",
      """,QUERY,({database_name}[^,]{1,2000}),""",
      """,QUERY,[^,]{0,2000},'(?:\/\*[^\/]{1,2000}\/)?\s{0,100}({db_operation}\w+)""",
      """,QUERY,[^,]{0,2000},'(?:\/\*[^\/]{1,2000}\/)?\s{0,100}({db_query}[^\}]{1,2000}?)\s{0,100}',({error_code}\d{1,100})?\s{0,100}""""
    ]
    DupFields = [ "host->dest_host" ]
  }
```