#### Parser Content
```Java
{
Name = cef-syslog-guardium-db-query
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Direct
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|IBM|Guardium|""", """cs3Label=Command""" ]
  Fields = [ """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """\sduser=(?:[^\\]*\\)?({db_user}.+?)\s+(\w+=|$)""",
    """\ssuser=((?:[^\s]+)?[\\\/])?({user}[^\\\/\s]+?)\s+(\w+=|$)""",
    """\scs5=(?: |({database_name}.+?))\s+(\w+=|$)""",
    """\scs2=({server_group}.+?)\s+(\w+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\s]+)""",
    """\scs3=({db_operation}.+?)\s+(\w+=|$)"""
    """\scn1=({response_size}\d+)"""
  ]
  DupFields = [ "db_user->account" ]
}
```