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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"exporter_time":"({time}\d{1,100}-\w+-\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})""",
    """"bytes_in":({bytes_in}\d{1,100})""",
    """"bytes_out":({bytes_out}\d{1,100})""",
    """"dest_ip":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"dest_port":({dest_port}\d{1,100})""",
    """"flow_end_time":({flow_end_time}\d{1,100})""",
    """"flow_start_time":({flow_start_time}\d{1,100})""",
    """"packets_in":({packets_in}\d{1,100})""",
    """"packets_out":({packets_out}\d{1,100})""",
    """"protoid":({protocol}\d{1,100})""",
    """"src_ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"src_port":({src_port}\d{1,100})""",
    """"tcp_flags":({tcp_flags}\d{1,100})""",
  ]
  DupFields = [ "bytes_in->bytes", "packets_in->packets"]


}
```