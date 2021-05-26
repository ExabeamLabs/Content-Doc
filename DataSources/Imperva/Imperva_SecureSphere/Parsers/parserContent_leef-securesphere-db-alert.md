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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """(\s|\|)devTime=({time}\w+ \w+ \d{1,100} \d\d:\d\d:\d\d \w+ \d\d\d\d)""",
    """(\s|\|)devTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(\s|\|)Alert ID=({alert_id}\d{1,100})""",
    """(\s|\|)Alert type=({alert_type}[^\|]{1,2000})""",
    """(\s|\|)src=({src_ip}[a-fA-F:\d\.]{1,2000})""",
    """(\s|\|)dst=({dest_ip}[a-fA-F:\d\.]{1,2000})""",
    """(\s|\|)usrName="{0,20}({user}[^\s\|"]{1,2000})""",
    """(\s|\|)Application name=({app}[^\|]{1,2000})""",
    """(\s|\|)Alert Description=({additional_info}[^\|]{1,2000})""",
    """(\s|\|)Severity=({alert_severity}[^\|]{1,2000})""",
    """(\s|\|)ServerGroupName=({server_group}[^\|]{1,2000})"""
  ]
  DupFields = [ "alert_type->alert_name" ]
}
```