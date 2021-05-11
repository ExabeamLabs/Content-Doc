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
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wdntdom=({user}[^\s]+)\s{0,100}(\w+=|$)""",
    """\Wduser=(NetApp Data ONTAP|({user}[^\s]+))\s{0,100}(\w+=|$)""",
    """\Wfname=({file_path}.+?)\s{0,100}(\w+=|$)""",
    """\Wfname=({file_parent}.+?)[^\\]+\s{0,100}(\w+=|$)""",
    """\Wfname=.*?({file_name}[^\\]+?)\s{0,100}(\w+=|$)""",
    """\Wfname=.*?(\.({file_ext}[^\\\.]+?))?\s{0,100}(\w+=|$)""",
    """\WfileId=(-|({file_id}\d{1,100}))""",
    """\WfileType=({file_type}.+?)\s{0,100}(\w+=|$)""",
    """CEF:([^\|]*\|){5}({accesses}[^\|]+)""",
    """\Wcs1=(-|({accesses}.+?))\s{0,100}(\w+=|$)"""
  ]
}
```