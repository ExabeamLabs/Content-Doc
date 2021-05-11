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
    """\w+ \d{1,2} \d{1,2}:\d{1,2}:\d{1,2}\s{0,100}({host}[\w\.-]+)""",
    """rule-desc=({alert_name}[^\^]+)(\^+|$)""",
    """category=({alert_type}[^\^]+)(\^+|$)""",
    """severity=({alert_severity}[^\^]+)(\^+|$)""",
    """sql=({additional_info}[^\^"]+?)(\^+|"|$)""",
    """client-hostname=([^\\]+\\)?({src_host}[\w\-\.]+)(\^+|$)""",
    """client-ip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """server-ip=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """service-name=({service_name}[^\^]+)(\^+|$)""",
    """server-type=({server_group}[^\^]+)(\^+|$)""",
    """src-program=({process}({directory}(?:[^\^]+)?[\\\/]+)?({process_name}[^\\\/\^]+))(\^+|$)""",
    """db-user=([^\\\^]+\\)?({db_user}[^\^]+)(\^+|$)""",
    """os-user=([^\\\^]+\\)?({user}[^\^]+)(\^+|$)"""
  ]
  DupFields = [ "db_user->account","directory->process_directory" ]
}
```