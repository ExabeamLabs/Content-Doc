#### Parser Content
```Java
{
Name = cef-snare-567
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "windows-567"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Snare|""", """|Security:567|Object Access Attempt|""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """CEF:([^\|]*\|){4}Security:({event_code}\d+)\|({event_name}[^\|]+)""",
    """\scategoryBehavior=(|({action}.+?))(\s+\w+=|\s*$)""",
    """\scategoryOutcome=(|/({outcome}.+?))(\s+\w+=|\s*$)""",
    """\scategoryObject=(|({object}.+?))(\s+\w+=|\s*$)""",
    """\sdhost=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\sduser=(|SYSTEM|({user}.+?))(\s+\w+=|\s*$)""",
    """Handle ID\\=({handle_id}\d+)""",
    """Process ID\\=({process_id}\d+)""",
    """Image File Name\\=({process}({directory}[^=&]*?[\\\/]+)?({process_name}[^=&\\\/]+?))&&Accesses\\=""",
    """Accesses\\=({accesses}[^=&]+)""",
    """User\\=(SYSTEM|({user}[^=&]+))""",
    """ComputerName\\=({host}[\w.\-]+)""",
  ]
}
```