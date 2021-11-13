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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}\w)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\Wfname=({object}.+?)\s{1,100}(\w+=|$)""",
    """\WsourceServiceName =({app}.+?)\s{1,100}(\w+=|$)""",
    """\WflexString1=({activity}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """\WdestinationServiceName =({event_subtype}.+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "user->user_email" ]


}
```