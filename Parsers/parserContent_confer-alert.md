#### Parser Content
```Java
{
Name = confer-alert
  Vendor = Carbon Black
  Product = CB Defense
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """"threatInfo"""",""""indicators"""",""""summary"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """eventTime"+:\s*({time}\d+)""",
    """email"+:\s*"+(({user_email}[^@"]+@[^"]+)|((({domain}[^\\"]+)\\+)?({user}[^"]+)))"""",
    """deviceName"+:\s*"+([^\\"]+\\+)?({src_host}[^"]+)"""",
    """ruleName"+:\s*"+(Confer - )?({alert_name}[^"]+)"""",
    """type"+:\s*"+({alert_type}[^"]+)"""",
    """incidentId"+:\s*"+({alert_id}[^"]+)"""",
    """score"+:\s*({alert_severity}\d+)""",
    """summary"+:\s*"+({additional_info}[^"]+)"""",
    """eventDescription"+:\s*"+({additional_info}[^"]+)"""",
    """deviceType"+:\s*"+({os}[^"]+)"""",
    """externalIpAddress"+:\s*"+({dest_ip}[^"]+)"""",
    """applicationName":\s"({process_name}[^"]+)""",
  ]
}
```