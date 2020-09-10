#### Parser Content
```Java
{
Name = cef-guardium-db-query
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Direct
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|IBM|Guardium|""", """cs3Label=Classification""", """act=SQL_""" ]
  Fields = [
    """\|rt=({time}\d+)""",
    """exabeam_host=({host}[^\s]+)""",
    """\ssuser=(:\w+=)?(?:|({user}.+?))\s*\w+=""",
    """\sduser=(?:[^\\=]*\\)?(?:|({db_user}.+?))\s+(\w+=|$)""",
    """\scs2=({server_group}.+?)\s+(\w+=|$)""",
    """\ssproc=(?:|({app}.+?))\s*([-(#].+?)?\s*\w+=""",
    """\ssrc=(?!0\.0\.0\.0)({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=(?!0\.0\.0\.0)({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\smsg=.*?({db_operation}(?i)(insert|delete|truncate|drop|alter|create|update|enable|disable|merge|delete|merge|select|dbcc))"""
  ]
  DupFields = [ "db_user->account" ]
}
```