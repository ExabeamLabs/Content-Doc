#### Parser Content
```Java
{
Name = cef-syslog-securesphere-db-alert
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Imperva|SecureSphere DAM|""", """cat=Alert""", """=ServerGroup""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\sduser=(?:n\/a|({user}.+?))\s*\w+=""",
    """\scs4=(?: |({app}.+?))\s*\w+=""",
    """\scs3=(?: |({service_name}.+?))\s*\w+=""",
    """\scs2=(?: |({server_group}.+?))\s*\w+=""",
    """\sflexString1=(?: |({database_name}.+?))\s+\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\scs5=({alert_name}.+?)(\s*\(\+\)| from| by| \w+=)""",
    """\scs1=({alert_type}.+?)\s\w+=""",
    """\seventId=({alert_id}\d+)""",
    """([^|]+\|){6}({alert_severity}[^|]+)""",
    """\sshost=({src_host}[^\s]+)""",
    """\sdhost=({dest_host}[^\s]+)"""
  ]
}
```