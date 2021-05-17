#### Parser Content
```Java
{
Name = cef-securesphere-db-alert
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Splunk
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Imperva Inc.|SecureSphere""", """cat=Alert""", """=ServerGroup""", """Query"""]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """cs7=\s{0,100}\(({time}\d\d \w+ \d{4} \d\d:\d\d:\d\d)\)\s{0,100}cs7Label=EventTime""",
    """rt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d ({host}.+?) CEF:""",
    """\sduser="{0,20}(?:n\/a|(({domain}[^\\\s"]{1,2000})\\+)?({user}[^\\\s"]{1,2000}?))"{0,20}\s{0,100}\w+=""",
    """\scs4=(?: |({app}.+?))\s{0,100}\w+=""",
    """\scs3=(?: |({service_name}.+?))\s{0,100}\w+=""",
    """\scs2=(?: |({server_group}.+?))\s{0,100}\w+=""",
    """\stable=(?: |({table_name}[^.,]{1,2000}))""",
    """\ssrc=(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\sdst=\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\scs5=({alert_name}.+?) (from|by|\w+=)""",
    """\scs1=({alert_type}.+?)\s{0,100}\w+=""",
    """alert_num=({alert_id}\d{1,100})""",
    """([^\|]{1,2000}\|){6}({alert_severity}[^|]{1,2000})""",
    """spt=({src_port}\d{1,100})""",
    """dpt=({dest_port}\d{1,100})"""
  ]
}
```