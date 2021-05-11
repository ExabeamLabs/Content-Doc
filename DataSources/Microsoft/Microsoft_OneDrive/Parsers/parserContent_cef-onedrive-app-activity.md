#### Parser Content
```Java
{
Name = cef-onedrive-app-activity
    Vendor = Microsoft
    Product = Microsoft OneDrive
    Lms = ArcSight
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """|Skyformation|SkyFormation Cloud Apps Security|""", """flexString1=PageViewed""" ]
    Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"CreationTime\\*"{1,20}:\\*\s{0,100}"{1,20}({time}[^\\"]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}\w)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsuser=(({user_email}[^@=\s]+?@[^=\s]+?)|(anonymous|({user}[^=\s@]+?)))\s{1,100}(\w+=|$)""",
    """"{1,20}UserId"{1,20}:"{1,20}({user_email}[^@\s"]+?@[^@\s"]+?)"{1,20}""",
    """\WfilePath=({object}[^=]+?)\s{1,100}(\w+=|$)""",
    """\WObjectUrl":"({object}[^"]+?)"""",
    """\WsourceServiceName=({app}[^=]+?)\s{1,100}(\w+=|$)""",
    """\WflexString1=({activity}[^=]+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]+?)\s{1,100}(\w+=|$)""",
    """\WdestinationServiceName=({event_subtype}[^=]+?)\s{1,100}(\w+=|$)""",
  ]
}
```