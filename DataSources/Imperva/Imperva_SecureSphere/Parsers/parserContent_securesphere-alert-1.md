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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\d\d:\d\d:\d\d ({host}\S+) SecSphWeb""",
    """AlertCreateTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """AlertInformation=({alert_name}[^;]+)""",
    """AlertType=({alert_type}[^;]+)""",
    """Severity=({alert_severity}[^;]+)""",
    """AlertDescription=({additional_info}[^;]+)""",
    """SourceIP=({src_ip}[A-Fa-f:\d.]+)""",
    """SourcePort=({src_port}\d{1,100})""",
    """AttackedApp=({app}[^;]+)""",
    """DestinationIP=({dest_ip}[A-Fa-f:\d.]+)""",
    """DestinationPort=({dest_port}\d{1,100})""",
    """EventNumber=({alert_id}\d{1,100})""",
    """Alert\.username=(n\/a|({user}[^;]+))""", 
  ]
}
```