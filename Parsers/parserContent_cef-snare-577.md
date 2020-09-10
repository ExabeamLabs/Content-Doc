#### Parser Content
```Java
{
Name = cef-snare-577
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-privileged-access"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Snare|""", """|Security:577|Privileged Service Called|""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """CEF:([^\|]*\|){4}Security:({event_code}\d+)\|({event_name}[^\|]+)""",
    """\scategoryBehavior=(|({action}.+?))(\s+\w+=|\s*$)""",
    """\scategoryOutcome=(|/({outcome}.+?))(\s+\w+=|\s*$)""",
    """\scategoryObject=(|({object}.+?))(\s+\w+=|\s*$)""",
    """\sdhost=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\sduser=(|SYSTEM|({user}.+?))(\s+\w+=|\s*$)""",
    """Primary User Name\\=(-|({user}[^=&]+))""",
    """Primary Domain\\=(-|({domain}[^=&]+))""",
    """Primary Logon ID\\=(-|({logon_id}[^=&]+))""",
    """Privileges\\=(-|({privileges}[^=&]+))""",
    """User\\=(SYSTEM|({user}[^=&]+))""",
    """ComputerName\\=({host}[\w.\-]+)""",
  ]
}
```