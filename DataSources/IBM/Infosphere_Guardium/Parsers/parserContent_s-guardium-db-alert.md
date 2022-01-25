#### Parser Content
```Java
{
Name = s-guardium-db-alert
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Splunk
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """GUARDIUM_ALERT""" ]
  Fields = [
    """session-start-time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d{1,2} \d{1,2}:\d{1,2}:\d{1,2}\s{0,100}({host}[\w\.-]{1,2000})""",
    """rule-desc=({alert_name}[^\^]{1,2000})(\^+|$)""",
    """category=({alert_type}[^\^]{1,2000})(\^+|$)""",
    """severity=({alert_severity}[^\^]{1,2000})(\^+|$)""",
    """sql=({additional_info}[^\^"]{1,2000}?)(\^+|"|$)""",
    """client-hostname=([^\\]{1,2000}\\)?({src_host}[\w\-\.]{1,2000})(\^+|$)""",
    """client-ip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """server-ip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """service-name=({service_name}[^\^]{1,2000})(\^+|$)""",
    """server-type=({server_group}[^\^]{1,2000})(\^+|$)""",
    """src-program=({process}({directory}(?:[^\^]{1,2000})?[\\\/]{1,2000})?({process_name}[^\\\/\^]{1,2000}))(\^+|$)""",
    """db-user=([^\\\^]{1,2000}\\)?({db_user}[^\^]{1,2000})(\^+|$)""",
    """os-user=([^\\\^]{1,2000}\\)?({user}[^\^]{1,2000})(\^+|$)"""
  ]
  DupFields = [ "db_user->account","directory->process_directory" ]
}
```