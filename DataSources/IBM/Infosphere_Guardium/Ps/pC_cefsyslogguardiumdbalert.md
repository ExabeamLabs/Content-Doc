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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\ssuser=({user}.+?)\s{0,100}\w+=""",
    """\sduser=(|({db_user}.+?))\s{0,100}\w+=""",
    """\scs3=(?: |({database_name}.+?))\s{0,100}\w+=""",
    """\scs2=({server_group}.+?)\s{0,100}\w+=""",
    """\ssrc=(0\.0\.0\.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=(({domain}[^=\\\/]{1,2000})[\\\/]{1,2000})?({src_host}[^\s\\\/=]{1,2000})""",
    """CEF.+?([^|]{1,2000}\|){5}({alert_name}[^|]{1,2000})""",
    """CEF.+?([^|]{1,2000}\|){6}({alert_severity}[^|]{1,2000})""",
    """\sdhost=({dest_host}[\w\-.]{1,2000})""",
    """\scs6=.*?({db_operation}(?i)(insert|delete|truncate|drop|alter|create|update|enable|disable|merge|delete|merge|select|dbcc))""",
    """\scs6=\s{0,100}({db_query}.+?)\s{1,100}\w+=""",
    """\scn3=({response_size}.+?)\s{1,100}\w+=""",
    """\scs4=(|({process_name}.+?))\s{1,100}\w+=""",
    """\sdvchost=(localhost|({host}[\w\-.]{1,2000}))"""
  ]
  DupFields = [ "alert_name->alert_type", "db_user->account", "db_query->additional_info" ]
}
```