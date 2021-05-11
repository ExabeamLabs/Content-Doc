#### Parser Content
```Java
{
Name = securesphere-alert
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|at=Securesphere Alert|""", """|g=""", """|u=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """exabeam_endTime=({time}\d{1,100})""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\|ad=({alert_name}.+?)( (from|by|in) .+?)?\|""",
    """\|an=({alert_type}[^|]+)""",
    """\|s=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|d=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|u=(?:n\/a|({user}[^|]+))""",
    """\|g=({process_name}.+?)\s{0,100}\|"""
  ]
}
```