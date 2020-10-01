#### Parser Content
```Java
{
Name = cef-exchange-app-activity
    Vendor = Microsoft
    Product = Exchange
    Lms = ArcSight
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """|Skyformation|SkyFormation Cloud Apps Security|""", """flexString1=HardDelete """, """request=Success""" ]
    Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+\w)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsuser=({user}.+?)\s+(\w+=|$)""",
    """\Wfname=({object}.+?)\s+(\w+=|$)""",
    """\WsourceServiceName=({app}.+?)\s+(\w+=|$)""",
    """\WflexString1=({activity}.+?)\s+(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
    """\WdestinationServiceName =({event_subtype}.+?)\s+(\w+=|$)""",
  ]
  DupFields = [ "user->user_email" ]
}
```