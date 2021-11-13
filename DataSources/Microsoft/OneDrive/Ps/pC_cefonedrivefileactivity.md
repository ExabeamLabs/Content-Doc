#### Parser Content
```Java
{
Name = cef-onedrive-file-activity
    Vendor = Microsoft
    Product = OneDrive
    Lms = ArcSight
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """|Skyformation|SkyFormation Cloud Apps Security|""", """flexString1=FileAccessed""", """sourceServiceName =OneDrive""" ]
    Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"CreationTime\\*"{1,20}:\\*\s{0,100}"{1,20}({time}[^\\"]{1,2000})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}\w) [\w\-.]{1,2000} Skyformation""",
    """\Wfname=\s{0,100}({file_name}.+?(\.({file_ext}[^\.\s]{1,2000}))?)\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsuser=(({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})|({user}[^\s]{1,2000}?))\s{1,100}(\w+=|$)""",
    """"{1,20}UserId"{1,20}:"{1,20}({user_email}[^@\s"]{1,2000}?@[^@\s"]{1,2000}?)"{1,20}"""
    """\WfilePath=({file_path}.+?)\s{1,100}(\w+=|$)""",
    """\WfilePath=\{"ObjectUrl":"({file_path}[^"]{1,2000}?)""""
    """\WrequestClientApplication=({process_name}.+?)\s{1,100}(\w+=|$)""",
    """\WfileType=({file_type}.+?)\s{1,100}(\w+=|$)""",
    """\WflexString1=({accesses}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=[^=]{0,2000}?\swas ({accesses}[^=]{1,2000}?) by"""
  ]


}
```