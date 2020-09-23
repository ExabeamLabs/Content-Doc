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
    """"CreationTime\\*"+:\\*\s*"+({time}[^\\"]+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+\w) ({host}[\w\-.]+) Skyformation""",
    """\Wfname=\s*({file_name}.+?(\.({file_ext}[^\.\s]+))?)\s+(\w+=|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsuser=(({user_email}[^\s@]+@[^\s@]+)|({user}[^\s]+?))\s+(\w+=|$)""",
    """"+UserId"+:"+({user_email}[^@\s"]+?@[^@\s"]+?)"+"""
    """\WfilePath=({file_path}.+?)\s+(\w+=|$)""",
    """\WfilePath=\{"ObjectUrl":"({file_path}[^"]+?)""""
    """\WrequestClientApplication=({process_name}.+?)\s+(\w+=|$)""",
    """\WfileType=({file_type}.+?)\s+(\w+=|$)""",
    """\WflexString1=({accesses}.+?)\s+(\w+=|$)""",
    """\Wmsg=[^=]*?\swas ({accesses}[^=]+?) by"""
  ]
}
```