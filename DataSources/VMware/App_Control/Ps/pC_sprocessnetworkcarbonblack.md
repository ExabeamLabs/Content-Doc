#### Parser Content
```Java
{
Name = s-process-network-carbonblack
  Vendor = VMware
  Product = App Control
  Lms = Splunk
  DataType = "process-network"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """"process_guid"""", """ingress.event.netconn""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """timestamp":({time}\d{10})""",
    """"type":"({activity_type}[^"]{1,2000})""",
    """computer_name":"({src_host}[^"]{1,2000})""",
    """sensor_id":({sensor_id}\d{1,100})""",
    """md5":"({md5}[^"]{1,2000})""",
    """"pid":({pid}\d{1,100})""",
    """"process_guid":"({process_guid}[^"]{1,2000})""",
    """local_ip":"({src_ip}[^"]{1,2000})""",
    """remote_ip":"({dest_ip}[^"]{1,2000})"""",
    """remote_port":({dest_port}[^\,"]{1,2000})""",
    """domain":"({web_domain}[^"]{1,2000})"""
  ]


}
```