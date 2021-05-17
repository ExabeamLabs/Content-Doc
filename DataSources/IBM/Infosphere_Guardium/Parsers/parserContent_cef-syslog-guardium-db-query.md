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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\sduser=(?:[^\\]{0,2000}\\)?({db_user}.+?)\s{1,100}(\w+=|$)""",
    """\ssuser=((?:[^\s]{1,2000})?[\\\/])?({user}[^\\\/\s]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\scs5=(?: |({database_name}.+?))\s{1,100}(\w+=|$)""",
    """\scs2=({server_group}.+?)\s{1,100}(\w+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """\scs3=({db_operation}.+?)\s{1,100}(\w+=|$)"""
    """\scn1=({response_size}\d{1,100})"""
  ]
  DupFields = [ "db_user->account" ]
}
```