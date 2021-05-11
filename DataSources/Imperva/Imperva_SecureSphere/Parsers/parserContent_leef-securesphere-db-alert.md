#### Parser Content
```Java
{
Name = leef-securesphere-db-alert
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = QRadar
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|Imperva|SecureSphere|""", """|Alert ID=""", """|Alert type=""", """|Alert Description=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """(\s|\|)devTime=({time}\w+ \w+ \d{1,100} \d\d:\d\d:\d\d \w+ \d\d\d\d)""",
    """(\s|\|)devTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(\s|\|)Alert ID=({alert_id}\d{1,100})""",
    """(\s|\|)Alert type=({alert_type}[^\|]+)""",
    """(\s|\|)src=({src_ip}[a-fA-F:\d\.]+)""",
    """(\s|\|)dst=({dest_ip}[a-fA-F:\d\.]+)""",
    """(\s|\|)usrName="{0,20}({user}[^\s\|"]+)""",
    """(\s|\|)Application name=({app}[^\|]+)""",
    """(\s|\|)Alert Description=({additional_info}[^\|]+)""",
    """(\s|\|)Severity=({alert_severity}[^\|]+)""",
    """(\s|\|)ServerGroupName=({server_group}[^\|]+)"""
  ]
  DupFields = [ "alert_type->alert_name" ]
}
```