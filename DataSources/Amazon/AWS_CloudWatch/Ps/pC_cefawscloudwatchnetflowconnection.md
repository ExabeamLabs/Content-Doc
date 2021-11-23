#### Parser Content
```Java
{
Name = cef-aws-cloudwatch-netflow-connection
  Vendor = Amazon
  Product = AWS CloudWatch
  Lms = ArcSight
  DataType = "netflow-connection"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName =AWS""", """dproc=CloudWatch Logs""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\Wstart=({time}\d{1,100})""",
    """\Wcat=(|({category}[^=]{1,2000}?))(\s{1,100}\w{1,100}=|\s{0,100}$)""",
    """\Wcn2=({bytes}\d{1,100})""",
    """\WdestinationServiceName =(|({service}[^=]{1,2000}?))(\s{1,100}\w{1,100}=|\s{0,100}$)""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wproto=(|({protocol}[^=]{1,2000}?))(\s{1,100}\w{1,100}=|\s{0,100}$)""",
    """\Wsuser=(|anonymous|({user}[^=]{1,2000}?))(\s{1,100}\w{1,100}=|\s{0,100}$)""",
    """\Wact=(|({outcome}[^=]{1,2000}?))(\s{1,100}\w{1,100}=|\s{0,100}$)"""
  ]


}
```