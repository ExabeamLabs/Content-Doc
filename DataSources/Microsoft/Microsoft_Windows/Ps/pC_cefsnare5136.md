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
    """\Wrt=({time}\d{1,100})""",
    """\Wsrc=({src_ip}[A-Fa-f0-9.:]{1,2000})""",
    """\Wdhost=({dest_host}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
    """\Wdvchost=({host}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[A-Fa-f0-9.:]{1,2000})""",
    """\Wdntdom=({domain}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
    """\Wduser=({user}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
    """\Wduid=({login_id}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
    """\WcategoryOutcome=\/?({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs5=(|({object_class}.+?))(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
    """\Wcs6=(|({object_dn}.+?))(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
    """\Wcs6=(|[^=]{0,2000}?({object_ou}OU.+?))(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
  ]


}
```