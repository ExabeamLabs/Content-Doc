#### Parser Content
```Java
{
Name = carbonblack-security-alert-2
  Vendor = VMware
  Product = VMware Carbon Black Cloud Endpoint Standard
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """cb-defense""", """indicatorName""" , """targetPriorityCode""", """targetPriorityType""" ,"""threat""" ]
  Fields = [
    """eventTime\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""",
    """"externalIpAddress\\":\\"({dest_ip}[^\\]+)\\"""",
    """"internalIpAddress\\":\\"({src_ip}[^\\]+)\\"""",
    """deviceName\\":\\"(({domain}[^\\"]+)\\+)?({src_host}[^"]+)\\"""",
    """deviceType\\":\\"({device_type}[^\\]+)\\"""",
    """score\\"{1,20}:\s{0,100}({alert_severity}\d{1,100})""",
    """agent.type\\":\\"({agent_name}[^"]+)\\"""",
    """host\\":\\"({host}[^"]+)\\"""",
    """type\\":\\"({threat_type}[^"]+)\\"""",
    """incidentId\\":\\"({threat_id}[^"]+)\\"""",
    """applicationName\\":\\"({process_name}[^"]+)\\"""",
    """threatCategory\\":\\"({category}[^"]+)\\"""",
    """indicatorName\\":\\"({alert_type}[^"]+)\\"""",
    """ruleName\\":\\"({alert_name}[^"]+)\\"""",
    """summary\\":\\"({addtional_info}[^"]+)\\"""",
    """email\\"{1,20}:\\s{0,100}"{1,20}(({domain}[^\\"]+)\\+)?({user}[^"]+)\\""",
    """deviceId\\"{1,20}:({sensor_id}[^,]+)"""
  ]
}
```