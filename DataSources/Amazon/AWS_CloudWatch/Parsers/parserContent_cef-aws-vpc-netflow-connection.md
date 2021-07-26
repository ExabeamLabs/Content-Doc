#### Parser Content
```Java
{
Name = cef-aws-vpc-netflow-connection
  Vendor = Amazon
  Product = AWS CloudWatch
  Lms = ArcSight
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """ requestClientApplication=AWS S3 Bucket""", """eni-""" , """ OK """ ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)\s{1,100}[\w.\-]{1,2000}\s{1,100}Skyformation""",
    """\Wcs6=(\S+\s{1,100}){4}({src_ip}[a-fA-F\d.:]{1,2000})\s{1,100}({dest_ip}[a-fA-F\d.:]{1,2000})\s{1,100}({src_port}\d{1,100})\s{1,100}({dest_port}\d{1,100})(\s{1,100}\S+){2}\s{1,100}({bytes}\d{1,100})""",
    """({outcome}\w+) OK\s{0,100}$""",
    """requestClientApplication=({app}.+?)\s\w+="""
  ]
}
```