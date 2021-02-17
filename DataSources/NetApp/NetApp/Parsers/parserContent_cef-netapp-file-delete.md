#### Parser Content
```Java
{
Name = cef-netapp-file-delete
  Vendor = NetApp
  Product = NetApp
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|NetApp|Filer|""", """|Object Open for Delete|""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wdntdom=({user}[^\s]+)\s*(\w+=|$)""",
    """\Wduser=(NetApp Data ONTAP|({user}[^\s]+))\s*(\w+=|$)""",
    """\Wfname=({file_path}.+?)\s*(\w+=|$)""",
    """\Wfname=({file_parent}.+?)[^\\]+\s*(\w+=|$)""",
    """\Wfname=.*?({file_name}[^\\]+?)\s*(\w+=|$)""",
    """\Wfname=.*?(\.({file_ext}[^\\\.]+?))?\s*(\w+=|$)""",
    """\WfileId=(-|({file_id}\d+))""",
    """\WfileType=({file_type}.+?)\s*(\w+=|$)""",
    """CEF:([^\|]*\|){5}({accesses}[^\|]+)""",
    """\Wcs1=(-|({accesses}.+?))\s*(\w+=|$)"""
  ]
}
```