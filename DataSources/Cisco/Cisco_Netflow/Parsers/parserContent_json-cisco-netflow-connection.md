#### Parser Content
```Java
{
Name = json-cisco-netflow-connection
  Vendor = Cisco
  Product = Cisco Netflow
  Lms = Direct
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MMM-dd HH:mm:ss"
  Conditions = [ """"bytes_in":""", """"exporter_time":"""", """"packets_in":""", """"tcp_flags":""", """"flow_start_time":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"exporter_time":"({time}\d+-\w+-\d+\s+\d+:\d+:\d+)""",
    """"bytes_in":({bytes_in}\d+)""",
    """"bytes_out":({bytes_out}\d+)""",
    """"dest_ip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"dest_port":({dest_port}\d+)""",
    """"flow_end_time":({flow_end_time}\d+)""",
    """"flow_start_time":({flow_start_time}\d+)""",
    """"packets_in":({packets_in}\d+)""",
    """"packets_out":({packets_out}\d+)""",
    """"protoid":({protocol}\d+)""",
    """"src_ip":"({src_ip}[A-Fa-f:\d.]+)""",
    """"src_port":({src_port}\d+)""",
    """"tcp_flags":({tcp_flags}\d+)""",
  ]
  DupFields = [ "bytes_in->bytes", "packets_in->packets"  ]
}
```