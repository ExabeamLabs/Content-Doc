#### Parser Content
```Java
{
Name = carbonblack-security-alert-2
  Vendor = Carbon Black
  Product = Cb Defense
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """cb-defense""", """indicatorName""" , """targetPriorityCode""", """targetPriorityType""" ,"""threat""" ]
  Fields = [
    """eventTime\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""",
    """"externalIpAddress\\":\\"({dest_ip}[^\\]+)\\"""",
    """"internalIpAddress\\":\\"({src_ip}[^\\]+)\\"""",
    """deviceName\\":\\"(({domain}[^\\"]+)\\+)?({src_host}[^"]+)\\"""",
    """deviceType\\":\\"({device_type}[^\\]+)\\"""",
    """score\\"+:\s*({alert_severity}\d+)""",
    """agent.type\\":\\"({agent_name}[^"]+)\\"""",
    """host\\":\\"({host}[^"]+)\\"""",
    """type\\":\\"({threat_type}[^"]+)\\"""",
    """incidentId\\":\\"({threat_id}[^"]+)\\"""",
    """applicationName\\":\\"({process_name}[^"]+)\\"""",
    """threatCategory\\":\\"({category}[^"]+)\\"""",
    """indicatorName\\":\\"({alert_type}[^"]+)\\"""",
    """ruleName\\":\\"({alert_name}[^"]+)\\"""",
    """summary\\":\\"({addtional_info}[^"]+)\\"""",
    """email\\"+:\\s*"+(({domain}[^\\"]+)\\+)?({user}[^"]+)\\""",
    """deviceId\\"+:({sensor_id}[^,]+)"""
  ]
}

${CarbonBlackParserTemplates.carbonblack-endpoint}{
  Name = carbonblack-endpoint-process-network
  DataType = "process-network"
  IsHVF = true
  Conditions = [ """netconn""" , """carbonblack""", """sensor_action""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-endpoint.Fields} [
    """"+local_ip"+:"+({src_ip}[^"]+)""",
    """"+remote_ip"+:"+({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """"+remote_port"+:({dest_port}\d+)"""
    """"+local_port"+:({src_port}\d+)"""
    """netconn_protocol"+:"+(PROTO_)?({protocol}[^"]+)""",
	]
}
```