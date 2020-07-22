#### Parser Content
```Java
{
Name = cef-syslog-guardium-db-alert
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Direct
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|IBM|Guardium|""", """cs3Label=DatabaseName""" ]
  Fields = [
    """\scs5=(({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)|({table_name}\w+))""",
    """exabeam_host=({host}[^\s]+)""",
    """\ssuser=({user}.+?)\s*\w+=""",
    """\sduser=(|({db_user}.+?))\s*\w+=""",
    """\scs3=(?: |({database_name}.+?))\s*\w+=""",
    """\scs2=({server_group}.+?)\s*\w+=""",
    """\ssrc=(0\.0\.0\.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=(({domain}[^=\\\/]+)[\\\/]+)?({src_host}[^\s\\\/=]+)""",
    """CEF.+?([^|]+\|){5}({alert_name}[^|]+)""",
    """CEF.+?([^|]+\|){6}({alert_severity}[^|]+)""",
    """\sdhost=({dest_host}[\w\-.]+)""",
    """\scs6=.*?({db_operation}(?i)(insert|delete|truncate|drop|alter|create|update|enable|disable|merge|delete|merge|select|dbcc))""",
    """\scs6=\s*({db_query}.+?)\s+\w+=""",
    """\scn3=({response_size}.+?)\s+\w+=""",
    """\scs4=(|({process_name}.+?))\s+\w+=""",
    """\sdvchost=(localhost|({host}[\w\-.]+))"""
  ]
  DupFields = [ "alert_name->alert_type", "db_user->account", "db_query->additional_info" ]
}
```