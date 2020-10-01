#### Parser Content
```Java
{
Name = s-process-network-carbonblack
  Vendor = Carbon Black
  Product = CB Protection
  Lms = Splunk
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """"process_guid"""", """ingress.event.netconn""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """timestamp":({time}\d{10})""",
    """"type":"({activity_type}[^"]+)""",
    """computer_name":"({src_host}[^"]+)""",
    """sensor_id":({sensor_id}\d+)""",
    """md5":"({md5}[^"]+)""",
    """"pid":({pid}\d+)""",
    """"process_guid":"({process_guid}[^"]+)""",
    """local_ip":"({src_ip}[^"]+)""",
    """remote_ip":"({dest_ip}[^"]+)"""",
    """remote_port":({dest_port}[^\,"]+)""",
    """domain":"({web_domain}[^"]+)"""
  ]
}
```