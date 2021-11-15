#### Parser Content
```Java
{
Name = carbonblack-endpoint-process-file
  DataType = "file-activity"
  IsHVF = true
  Conditions = [ """filemod""" , """carbonblack""" , """sensor_action"""]
  Fields = ${CarbonBlackParserTemplates.carbonblack-endpoint.Fields} [
    ]

carbonblack-endpoint{
  Vendor = VMware
  Product = App Control
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}.\d\d\d)""",
    """"{1,20}process_cmdline"{1,20}:"{1,20}({command_line}[^"]{1,2000})"{1,20}""",
    """"{1,20}process_username"{1,20}:"{1,20}(({domain}[^\\,]{1,2000})\\+)?(SYSTEM|({user}[^",]{1,2000}))"{1,20}""",
    """"{1,20}process_pid"{1,20}:({pid}\d{1,100})""",
    """"{1,20}device_name"{1,20}:\s{0,100}"{1,20}(\w+\\+)?({host}[^."]{1,2000})""",
    """"{1,20}sensor_action"{1,20}:"{1,20}({outcome}[^"]{1,2000})"{1,20}""",
    """"{1,20}process_path"{1,20}:"{1,20}({process}({directory}[^"]{1,2000}(\\|\/)+)?({process_name}[^"]{1,2000}))"""",
    """"{1,20}action"{1,20}:"{1,20}({action}[^"]{1,2000})?"{0,20}""",
    """"{1,20}parent_cmdline"{1,20}:"{1,20}({parent_cmd}[^,]{1,2000}"{1,20})?"\,""",
    """"{1,20}parent_pid"{1,20}:({parent_pid}\d{1,100})""",
    """"{1,20}process_guid"{1,20}:"{1,20}({process_guid}[^"]{1,2000})?"{0,20}\,""",
    """"{1,20}parent_guid"{1,20}:"{1,20}({parent_process_guid}[^"]{1,2000})?"{0,20}\,""",
    """"{1,20}alert_id"{1,20}:"{1,20}({alert_id}[^,]"{1,20})?\,""",
    """"{1,20}type"{1,20}:"{1,20}({activity_type}[^"]{1,2000})"{1,20}"""

   
}
```