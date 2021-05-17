#### Parser Content
```Java
{
Name = cef-netapp-file-read
  Vendor = NetApp
  Product = NetApp
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|NetApp|Filer|""", """|Object Open|""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdntdom=({user}[^\s]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wduser=(NetApp Data ONTAP|({user}[^\s]{1,2000}))\s{0,100}(\w+=|$)""",
    """\Wfname=({file_path}.+?)\s{0,100}(\w+=|$)""",
    """\Wfname=({file_parent}.+?)[^\\]{1,2000}\s{0,100}(\w+=|$)""",
    """\Wfname=.*?({file_name}[^\\]{1,2000}?)\s{0,100}(\w+=|$)""",
    """\Wfname=.*?(\.({file_ext}[^\\\.]{1,2000}?))?\s{0,100}(\w+=|$)""",
    """\WfileId=(-|({file_id}\d{1,100}))""",
    """\WfileType=({file_type}.+?)\s{0,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){5}({accesses}[^\|]{1,2000})""",
    """\Wcs1=(-|({accesses}.+?))\s{0,100}(\w+=|$)"""
  ]
}
```