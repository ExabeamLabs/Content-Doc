#### Parser Content
```Java
{
Name = cef-aws-cloudwatch-netflow-connection
  Vendor = Amazon
  Product = AWS CloudWatch
  Lms = ArcSight
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """destinationServiceName =AWS""", """dproc=CloudWatch""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) [\w.\-]{1,2000} Skyformation""",
    """\Wcat=(|({category}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcn2=({bytes}\d{1,100})""",
    """\WdestinationServiceName =(|({service}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wproto=(|({protocol}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsuser=(|anonymous|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wact=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]


}
```