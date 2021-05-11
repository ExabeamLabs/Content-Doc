#### Parser Content
```Java
{
Name = cef-snare-578
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-privileged-access"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Snare|""", """|Security:578|Privileged object operation|""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """CEF:([^\|]*\|){4}Security:({event_code}\d{1,100})\|({event_name}[^\|]+)""",
    """\scategoryBehavior=(|({action}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\scategoryOutcome=(|/({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\scategoryObject=(|({object}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\sduser=(|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """Process ID\\=({process_id}\d{1,100})""",
    """Primary User Name\\=(-|({user}[^=&]+))""",
    """Primary Domain\\=(-|({domain}[^=&]+))""",
    """Primary Logon ID\\=(-|({logon_id}[^=&]+))""",
    """Privileges\\=(-|({privileges}[^=&]+))""",
    """User\\=(-|({user}[^=&]+))""",
    """ComputerName\\=({host}[\w.\-]+)""",
  ]
}
```