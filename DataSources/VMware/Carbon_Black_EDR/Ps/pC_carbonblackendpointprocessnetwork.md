#### Parser Content
```Java
{
Name = carbonblack-endpoint-process-network
  DataType = "process-network"
  IsHVF = true
  Conditions = [ """netconn""" , """carbonblack""", """sensor_action""" ]
  Fields = ${CarbonBlackParserTemplates.carbonblack-endpoint.Fields} [
    """"{1,20}local_ip"{1,20}:"{1,20}({src_ip}[^"]{1,2000})""",
    """"{1,20}remote_ip"{1,20}:"{1,20}({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """"{1,20}remote_port"{1,20}:({dest_port}\d{1,100})"""
    """"{1,20}local_port"{1,20}:({src_port}\d{1,100})"""
    """netconn_protocol"{1,20}:"{1,20}(PROTO_)?({protocol}[^"]{1,2000})""",
    ]
    DupFields = ["activity_type->event_name"]

carbonblack-endpoint{
  Vendor = VMware
  Product = Carbon Black EDR
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