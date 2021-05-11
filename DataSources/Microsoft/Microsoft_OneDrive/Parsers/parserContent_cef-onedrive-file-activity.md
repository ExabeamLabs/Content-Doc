#### Parser Content
```Java
{
Name = cef-onedrive-file-activity
    Vendor = Microsoft
    Product = Microsoft OneDrive
    Lms = ArcSight
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """|Skyformation|SkyFormation Cloud Apps Security|""", """flexString1=FileAccessed""", """sourceServiceName=OneDrive""" ]
    Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"CreationTime\\*"{1,20}:\\*\s{0,100}"{1,20}({time}[^\\"]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}\w) [\w\-.]+ Skyformation""",
    """\Wfname=\s{0,100}({file_name}.+?(\.({file_ext}[^\.\s]+))?)\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsuser=(({user_email}[^\s@]+@[^\s@]+)|({user}[^\s]+?))\s{1,100}(\w+=|$)""",
    """"{1,20}UserId"{1,20}:"{1,20}({user_email}[^@\s"]+?@[^@\s"]+?)"{1,20}"""
    """\WfilePath=({file_path}.+?)\s{1,100}(\w+=|$)""",
    """\WfilePath=\{"ObjectUrl":"({file_path}[^"]+?)""""
    """\WrequestClientApplication=({process_name}.+?)\s{1,100}(\w+=|$)""",
    """\WfileType=({file_type}.+?)\s{1,100}(\w+=|$)""",
    """\WflexString1=({accesses}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=[^=]*?\swas ({accesses}[^=]+?) by"""
  ]
}
```