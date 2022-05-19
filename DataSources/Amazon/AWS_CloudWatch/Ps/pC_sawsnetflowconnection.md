#### Parser Content
```Java
{
Name = s-aws-netflow-connection
  Vendor = Amazon
  Product = AWS CloudWatch
  Lms = Splunk
  DataType = "netflow-connection"
  TimeFormat = "epoch"
  Conditions = [ """ eni-""", """ ACCEPT OK"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(gcs-topic|({host}\S+))""",
    """requestClientApplication=({host}[^\s]{1,2000})\s""",
    """(unknown|({account_id}\S+)) ({interface_id}\S+) ({src_ip}[A-Fa-f:\d.]{1,2000}) ({dest_ip}[A-Fa-f:\d.]{1,2000}) ({src_port}\d{1,100}) ({dest_port}\d{1,100}) ({protocol}\S+) ({packets}\S+) ({bytes}\d{1,100}) ({time}\d{1,100}) \S+ ({action}\S+) ({outcome}[^"\\\s]{1,2000})""",
  ]


}
```