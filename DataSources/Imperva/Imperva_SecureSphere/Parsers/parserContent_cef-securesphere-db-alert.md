#### Parser Content
```Java
{
Name = cef-securesphere-db-alert
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Splunk
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "dd MMMM yyyy HH:mm:ss"
  Conditions = [ """|Imperva Inc.|SecureSphere""", """cat=Alert""", """=ServerGroup""", """Query"""]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """cs7=\s*\(({time}\d\d \w+ \d{4} \d\d:\d\d:\d\d)\)\s*cs7Label=EventTime""",
    """\d\d:\d\d:\d\d ({host}.+?) CEF:""",
    """\sduser="*(?:n\/a|(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+?))"*\s*\w+=""",
    """\scs4=(?: |({app}.+?))\s*\w+=""",
    """\scs3=(?: |({service_name}.+?))\s*\w+=""",
    """\scs2=(?: |({server_group}.+?))\s*\w+=""",
    """\stable=(?: |({table_name}[^.,]+))""",
    """\ssrc=(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\sdst=\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\scs5=({alert_name}.+?) (from|by|\w+=)""",
    """\scs1=({alert_type}.+?)\s*\w+=""",
    """alert_num=({alert_id}\d+)""",
    """([^\|]+\|){6}({alert_severity}[^|]+)""",
    """spt=({src_port}\d+)""",
    """dpt=({dest_port}\d+)"""
  ]
}
```