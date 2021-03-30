#### Parser Content
```Java
{
Name = cef-snare-5136
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-ds-access"
  TimeFormat = "epoch"
  Conditions = [ "|Snare|", "A directory service object was modified"]
  Fields = [
    """({event_name}A directory service object was modified)""",
    """({event_code}5136)""",
    """\Wrt=({time}\d+)""",
    """\Wsrc=({src_ip}[A-Fa-f0-9.:]+)""",
    """\Wdhost=({dest_host}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\Wdvchost=({host}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\Wdst=({dest_ip}[A-Fa-f0-9.:]+)""",
    """\Wdntdom=({domain}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\Wduser=({user}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\Wduid=({login_id}.+?)(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\WcategoryOutcome=\/?({outcome}.+?)\s+(\w+=|$)""",
    """\Wcs5=(|({object_class}.+?))(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\Wcs6=(|({object_dn}.+?))(\s+(\w+|\w+\.\w+)=|\s*$)""",
    """\Wcs6=(|[^=]*?({object_ou}OU.+?))(\s+(\w+|\w+\.\w+)=|\s*$)""",
  ]
}
```