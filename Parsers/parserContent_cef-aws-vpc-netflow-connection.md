#### Parser Content
```Java
{
Name = cef-aws-vpc-netflow-connection
  Vendor = AWS
  Product = AWS CloudWatch
  Lms = ArcSight
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """ requestClientApplication=AWS S3 Bucket""", """eni-""" , """ OK """ ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)\s+[\w.\-]+\s+Skyformation""",
    """\Wcs6=(\S+\s+){4}({src_ip}[a-fA-F\d.:]+)\s+({dest_ip}[a-fA-F\d.:]+)\s+({src_port}\d+)\s+({dest_port}\d+)(\s+\S+){2}\s+({bytes}\d+)""",
    """({outcome}\w+) OK\s*$""",
    """requestClientApplication=({app}.+?)\s\w+="""
  ]
}
```