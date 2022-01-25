#### Parser Content
```Java
{
Name = cc-carbonblack-edr-crossproc
  DataType = "process-created"
  Conditions = [ """CEF:""", """|Skyformation|""", """requestClientApplication=""" , """"type":"endpoint.event.crossproc"""", """destinationServiceName =""", """"process_username":"""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-edr.Fields} [
    """"parent_path":"({parent_process}({parent_directory}[^"]{1,2000}(\\|\/)+)?({parent_process_name}[^"]{1,2000}))"""",
  ]

carbonblack-edr {
  Vendor = VMware
  Product = Endpoint Detection and Response 
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Fields = [
    """"{1,20}process_cmdline"{1,20}:"{1,20}\s{0,100}({command_line}[^"]{1,2000}?)\s{0,100}"{1,20},""",
    """"{1,20}process_username"{1,20}:"{1,20}(({domain}[^\\,]{1,2000})\\+)?(Citrix Delivery Services Resources|SYSTEM|NETWORK SERVICE|LOCAL SERVICE|({user}[^",]{1,2000}))"{1,20}""",
    """"{1,20}process_pid"{1,20}:({pid}\d{1,100})""",
    """"{1,20}device_name"{1,20}:\s{0,100}"{1,20}(\w+\\+)?({host}[^."]{1,2000})""",
    """"{1,20}sensor_action"{1,20}:"{1,20}({outcome}[^"]{1,2000})"{1,20}""",
    """"{1,20}process_path"{1,20}:"{1,20}((?i)(SYSTEM)|({process}({directory}[^"]{1,2000}(\\|\/)+)?({process_name}[^"]{1,2000})))"""",
    """"{1,20}action"{1,20}:"{1,20}({action}[^"]{1,2000})?"{0,20}""",
    """"{1,20}parent_cmdline"{1,20}:"{1,20}\s{0,100}({parent_cmd}[^,"]{1,2000})""",
    """"{1,20}parent_pid"{1,20}:({parent_pid}\d{1,100})""",
    """"{1,20}process_guid"{1,20}:"{1,20}({process_guid}[^"]{1,2000})?"{0,20}\,""",
    """"{1,20}parent_guid"{1,20}:"{1,20}({parent_process_guid}[^"]{1,2000})?"{0,20}\,""",
    """"{1,20}alert_id"{1,20}:"{1,20}({alert_id}[^,]"{1,20})?\,""",
    """"{1,20}type"{1,20}:"{1,20}({activity_type}[^"]{1,2000})"{1,20}""",
    """"device_id"{1,20}:"{1,20}({device_id}[^",]{1,2000})""",
    """"device_external_ip"{1,20}:"{1,20}({dest_ip}[^",]{1,2000})""",
    """"device_timestamp"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)"""
  ]
  DupeFields = ["directory->process_directory"
}
```