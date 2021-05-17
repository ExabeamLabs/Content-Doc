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
}
```