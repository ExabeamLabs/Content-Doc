#### Parser Content
```Java
{
Name = cef-snare-5140
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "share-access"
  TimeFormat = "epoch"
  Conditions = [ "|Snare|", "A network share object was accessed", "Microsoft-Windows-Security-Auditing:5140|"]
  Fields = [
    """({event_name}A network share object was accessed)""",
    """({event_code}5140)""",
    """\Wrt=({time}\d+)""",
    """\Wsrc=({src_ip}[A-Fa-f0-9.:]+)""",
    """\Wdhost=({dest_host}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\Wdvchost=({host}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\Wdst=({dest_ip}[A-Fa-f0-9.:]+)""",
    """\Wdntdom=({domain}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\Wduser=({user}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\Wduid=({login_id}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\WfilePath=(?:\\+\*\\+)?({share_name}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """({accesses}Read)""",
    """\Wad\.ShareLocalPath=(?:[\\\?]+)?(?:\s*|({share_path}({d_parent}.*?)({d_name}[^\\]+?))(\\+)?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\WfileType=({file_type}\w+)""",
    """\WcategoryOutcome=\/?({outcome}.+?)\s+(\w+=|$)""",
    """\WObject Type:\s*({file_type}.+?)\s+Source Address:\s*({src_ip}[A-Fa-f:\d.]+)""",
    """\WShare Name:\s*({share_name}.+?)\s+Share Path:""",
    """\WShare Path:\s*(|({share_path}({d_parent}.*?[\\\/]+)?(|({d_name}[^\\]+?))))\s+Access Request Information:""",
  ]
}
```