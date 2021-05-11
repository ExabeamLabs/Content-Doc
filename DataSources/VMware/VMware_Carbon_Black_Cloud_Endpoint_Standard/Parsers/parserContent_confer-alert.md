#### Parser Content
```Java
{
Name = confer-alert
  Vendor = VMware
  Product = VMware Carbon Black Cloud Endpoint Standard
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """"threatInfo"""",""""indicators"""",""""summary"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """eventTime"{1,20}:\s{0,100}({time}\d{1,100})""",
    """email"{1,20}:\s{0,100}"{1,20}(({user_email}[^@"]+@[^"]+)|((({domain}[^\\"]+)\\+)?({user}[^"]+)))"""",
    """deviceName"{1,20}:\s{0,100}"{1,20}([^\\"]+\\+)?({src_host}[^"]+)"""",
    """ruleName"{1,20}:\s{0,100}"{1,20}(Confer - )?({alert_name}[^"]+)"""",
    """type"{1,20}:\s{0,100}"{1,20}({alert_type}[^"]+)"""",
    """incidentId"{1,20}:\s{0,100}"{1,20}({alert_id}[^"]+)"""",
    """score"{1,20}:\s{0,100}({alert_severity}\d{1,100})""",
    """summary"{1,20}:\s{0,100}"{1,20}({additional_info}[^"]+)"""",
    """eventDescription"{1,20}:\s{0,100}"{1,20}({additional_info}[^"]+)"""",
    """deviceType"{1,20}:\s{0,100}"{1,20}({os}[^"]+)"""",
    """externalIpAddress"{1,20}:\s{0,100}"{1,20}({dest_ip}[^"]+)"""",
    """applicationName":\s"({process_name}[^"]+)""",
  ]
}
```