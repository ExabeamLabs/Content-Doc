#### Parser Content
```Java
{
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
    DupFields = ["activity_type->event_name"]
}
```