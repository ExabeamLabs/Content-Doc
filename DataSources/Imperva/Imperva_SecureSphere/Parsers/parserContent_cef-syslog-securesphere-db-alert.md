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
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sduser=(?:n\/a|({user}.+?))\s{0,100}\w+=""",
    """\scs4=(?: |({app}.+?))\s{0,100}\w+=""",
    """\scs3=(?: |({service_name}.+?))\s{0,100}\w+=""",
    """\scs2=(?: |({server_group}.+?))\s{0,100}\w+=""",
    """\sflexString1=(?: |({database_name}.+?))\s{1,100}\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\scs5=({alert_name}.+?)(\s{0,100}\(\+\)| from| by| \w+=)""",
    """\scs1=({alert_type}.+?)\s\w+=""",
    """\seventId=({alert_id}\d{1,100})""",
    """([^|]{1,2000}\|){6}({alert_severity}[^|]{1,2000})""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """\sdhost=({dest_host}[^\s]{1,2000})"""
  ]
}
```