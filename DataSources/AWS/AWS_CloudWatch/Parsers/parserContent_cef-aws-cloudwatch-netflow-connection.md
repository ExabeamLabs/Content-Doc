#### Parser Content
```Java
{
Name = cef-aws-cloudwatch-netflow-connection
  Vendor = AWS
  Product = AWS CloudWatch
  Lms = ArcSight
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """destinationServiceName=AWS""", """dproc=CloudWatch""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) [\w.\-]+ Skyformation""",
    """\Wcat=(|({category}.+?))(\s+\w+=|\s*$)""",
    """\Wcn2=({bytes}\d+)""",
    """\WdestinationServiceName=(|({service}.+?))(\s+\w+=|\s*$)""",
    """\Wdpt=({dest_port}\d+)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wspt=({src_port}\d+)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wproto=(|({protocol}.+?))(\s+\w+=|\s*$)""",
    """\Wsuser=(|anonymous|({user}.+?))(\s+\w+=|\s*$)""",
    """\Wact=(|({outcome}.+?))(\s+\w+=|\s*$)""",
  ]
}
```