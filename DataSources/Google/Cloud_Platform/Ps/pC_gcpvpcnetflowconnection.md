#### Parser Content
```Java
{
Name = gcpvpc-netflow-connection
  Vendor = Google
  Product = Cloud Platform
  Lms = Direct
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"jsonPayload":""", """"vm_name":""", """"vpc_name":""", """"gce_subnetwork"""" ]
  Fields = [
    """\w{3}\s\d\d\s\d\d:\d\d:\d\d\s(::ffff:)?({host}[\w\-.]{1,2000})\s\d{1,100}\s""",
    """"start_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"vpc_name":"(::ffff:)?(default|({host}[^"]{1,2000}))""",
    """"src_ip":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"src_port":({src_port}\d{1,100})""",
    """"protocol":({protocol}\d{1,100})""",
    """"dest_ip":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"dest_port":({dest_port}\d{1,100})""",
    """"bytes_sent":"({bytes_out}\d{1,100})""",
    """"packets_sent":"({packets}\d{1,100})""",
    """"dest_instance":\{[^\}]{0,2000}?"vm_name":"({dest_host}[^"]{1,2000})""",
    """"src_instance":\{[^\}]{0,2000}?"vm_name":"({src_host}[^"]{1,2000})""",
    """"reporter":"({reporter}[^"]{1,2000})""",
  ]


}
```