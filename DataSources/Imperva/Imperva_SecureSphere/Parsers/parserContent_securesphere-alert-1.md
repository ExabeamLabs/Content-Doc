#### Parser Content
```Java
{
Name = securesphere-alert-1
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """SecSphWeb""", """;AlertInformation=""", """;AlertType=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\d\d:\d\d:\d\d ({host}\S+) SecSphWeb""",
    """AlertCreateTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """AlertInformation=({alert_name}[^;]{1,2000})""",
    """AlertType=({alert_type}[^;]{1,2000})""",
    """Severity=({alert_severity}[^;]{1,2000})""",
    """AlertDescription=({additional_info}[^;]{1,2000})""",
    """SourceIP=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """SourcePort=({src_port}\d{1,100})""",
    """AttackedApp=({app}[^;]{1,2000})""",
    """DestinationIP=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """DestinationPort=({dest_port}\d{1,100})""",
    """EventNumber=({alert_id}\d{1,100})""",
    """Alert\.username=(n\/a|({user}[^;]{1,2000}))""", 
  ]
}
```