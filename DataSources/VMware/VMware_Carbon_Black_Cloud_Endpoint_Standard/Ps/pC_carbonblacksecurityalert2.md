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
    """"externalIpAddress\\":\\"({dest_ip}[^\\]{1,2000})\\"""",
    """"internalIpAddress\\":\\"({src_ip}[^\\]{1,2000})\\"""",
    """deviceName\\":\\"(({domain}[^\\"]{1,2000})\\+)?({src_host}[^"]{1,2000})\\"""",
    """deviceType\\":\\"({device_type}[^\\]{1,2000})\\"""",
    """score\\"{1,20}:\s{0,100}({alert_severity}\d{1,100})""",
    """agent.type\\":\\"({agent_name}[^"]{1,2000})\\"""",
    """host\\":\\"({host}[^"]{1,2000})\\"""",
    """type\\":\\"({threat_type}[^"]{1,2000})\\"""",
    """incidentId\\":\\"({threat_id}[^"]{1,2000})\\"""",
    """applicationName\\":\\"({process_name}[^"]{1,2000})\\"""",
    """threatCategory\\":\\"({category}[^"]{1,2000})\\"""",
    """indicatorName\\":\\"({alert_type}[^"]{1,2000})\\"""",
    """ruleName\\":\\"({alert_name}[^"]{1,2000})\\"""",
    """summary\\":\\"({addtional_info}[^"]{1,2000})\\"""",
    """email\\"{1,20}:\\s{0,100}"{1,20}(({domain}[^\\"]{1,2000})\\+)?({user}[^"]{1,2000})\\""",
    """deviceId\\"{1,20}:({sensor_id}[^,]{1,2000})"""
  ]


}
```