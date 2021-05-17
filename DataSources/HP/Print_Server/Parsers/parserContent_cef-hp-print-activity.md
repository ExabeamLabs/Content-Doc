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
    """\srt=({time}\d{1,100})""",
    """\sshost=({src_host}.+?)\s{1,100}(\w+=|$)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})\s{1,100}(\w+=|$)""",
    """\ssntdom=({domain}.+?)\s{1,100}(\w+=|$)""",
    """\ssuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]{1,2000})\s{1,100}(\w+=|$)""",
    """\ssuid=({user_fullname}.+?)\s{1,100}(\w+=|$)""",
    """\sfname=({object}.+?)\s{1,100}(\w+=|$)""",
    """\scs1=({printer_name}.+?)\s{1,100}(\w+=|$)""",
    """\scs2=({printer_id}.+?)\s{1,100}(\w+=|$)""",
    """\scs3=({dest_host}.+?)\s{1,100}(\w+=|$)""",
    """\scn1=({num_pages}\d{1,100})""",
    """\sdvc=({host}.+?)\s{1,100}(\w+=|$)""",
    """\sdvchost=({host}.+?)\s{1,100}(\w+=|$)""",
    """CEF:([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})\|""",
  ]
}
```