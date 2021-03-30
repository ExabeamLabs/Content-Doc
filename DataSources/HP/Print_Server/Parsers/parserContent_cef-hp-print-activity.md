#### Parser Content
```Java
{
Name = cef-hp-print-activity
  Vendor = HP
  Product = Print Server
  Lms = ArcSight
  DataType = "print-activity"
  TimeFormat =  "epoch"
  Conditions = [ """CEF:""", """|HP|Print Server|""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sshost=({src_host}.+?)\s+(\w+=|$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)\s+(\w+=|$)""",
    """\ssntdom=({domain}.+?)\s+(\w+=|$)""",
    """\ssuser=({user}.+?)\s+(\w+=|$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)\s+(\w+=|$)""",
    """\ssuid=({user_fullname}.+?)\s+(\w+=|$)""",
    """\sfname=({object}.+?)\s+(\w+=|$)""",
    """\scs1=({printer_name}.+?)\s+(\w+=|$)""",
    """\scs2=({printer_id}.+?)\s+(\w+=|$)""",
    """\scs3=({dest_host}.+?)\s+(\w+=|$)""",
    """\scn1=({num_pages}\d+)""",
    """\sdvc=({host}.+?)\s+(\w+=|$)""",
    """\sdvchost=({host}.+?)\s+(\w+=|$)""",
    """CEF:([^\|]*\|){5}({activity}[^\|]+)\|""",
  ]
}
```