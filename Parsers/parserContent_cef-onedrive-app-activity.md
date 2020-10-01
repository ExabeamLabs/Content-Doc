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
    """"CreationTime\\*"+:\\*\s*"+({time}[^\\"]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+\w)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsuser=(({user_email}[^@=\s]+?@[^=\s]+?)|(anonymous|({user}[^=\s@]+?)))\s+(\w+=|$)""",
    """"+UserId"+:"+({user_email}[^@\s"]+?@[^@\s"]+?)"+""",
    """\WfilePath=({object}[^=]+?)\s+(\w+=|$)""",
    """\WObjectUrl":"({object}[^"]+?)"""",
    """\WsourceServiceName=({app}[^=]+?)\s+(\w+=|$)""",
    """\WflexString1=({activity}[^=]+?)\s+(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]+?)\s+(\w+=|$)""",
    """\WdestinationServiceName=({event_subtype}[^=]+?)\s+(\w+=|$)""",
  ]
}
```