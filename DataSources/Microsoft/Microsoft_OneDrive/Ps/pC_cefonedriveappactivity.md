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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"CreationTime\\*"{1,20}:\\*\s{0,100}"{1,20}({time}[^\\"]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}\w)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsuser=(({user_email}[^@=\s]{1,2000}?@[^=\s]{1,2000}?)|(anonymous|({user}[^=\s@]{1,2000}?)))\s{1,100}(\w+=|$)""",
    """"{1,20}UserId"{1,20}:"{1,20}({user_email}[^@\s"]{1,2000}?@[^@\s"]{1,2000}?)"{1,20}""",
    """\WfilePath=({object}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\WObjectUrl":"({object}[^"]{1,2000}?)"""",
    """\WsourceServiceName =({app}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\WflexString1=({activity}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\WdestinationServiceName =({event_subtype}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
  ]


}
```