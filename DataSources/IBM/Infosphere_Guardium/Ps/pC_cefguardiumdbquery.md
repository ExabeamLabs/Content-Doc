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
    """\|rt=({time}\d{1,100})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\ssuser=(:\w+=)?(?:|({user}.+?))\s{0,100}\w+=""",
    """\sduser=(?:[^\\=]{0,2000}\\)?(?:|({db_user}.+?))\s{1,100}(\w+=|$)""",
    """\scs2=({server_group}.+?)\s{1,100}(\w+=|$)""",
    """\ssproc=(?:|({app}.+?))\s{0,100}([-(#].+?)?\s{0,100}\w+=""",
    """\ssrc=(?!0\.0\.0\.0)({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=(?!0\.0\.0\.0)({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\smsg=.*?({db_operation}(?i)(insert|delete|truncate|drop|alter|create|update|enable|disable|merge|delete|merge|select|dbcc))"""
  ]
  DupFields = [ "db_user->account" ]
}
```