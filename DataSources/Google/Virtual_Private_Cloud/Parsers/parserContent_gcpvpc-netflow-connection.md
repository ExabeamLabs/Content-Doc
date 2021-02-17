#### Parser Content
```Java
{
Name = gcpvpc-netflow-connection
  Vendor = Google
  Product = Virtual Private Cloud
  Lms = Direct
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"jsonPayload":""", """"vm_name":""", """"vpc_name":""", """"gce_subnetwork"""" ]
  Fields = [
    """"start_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"vpc_name":"({host}[^"]+)""",
    """"src_ip":"({src_ip}[a-fA-F\d.:]+)""",
    """"src_port":({src_port}\d+)""",
    """"protocol":({protocol}\d+)""",
    """"dest_ip":"({dest_ip}[a-fA-F\d.:]+)""",
    """"dest_port":({dest_port}\d+)""",
    """"bytes_sent":"({bytes_out}\d+)""",
    """"packets_sent":"({packets}\d+)""",
    """"dest_instance":\{.*?"vm_name":"({dest_host}[^"]+)""",
    """"src_instance":\{.*?"vm_name":"({src_host}[^"]+)""",
    """"reporter":"({reporter}[^"]+)""",
  ]
}
```