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
    """\srt=({time}\d{1,100})""",
    """CEF:([^\|]*\|){4}Security:({event_code}\d{1,100})\|({event_name}[^\|]+)""",
    """\scategoryBehavior=(|({action}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\scategoryOutcome=(|/({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\scategoryObject=(|({object}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\sduser=(|SYSTEM|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """Handle ID\\=({handle_id}\d{1,100})""",
    """Process ID\\=({process_id}\d{1,100})""",
    """Image File Name\\=({process}({directory}[^=&]*?[\\\/]+)?({process_name}[^=&\\\/]+?))&&Accesses\\=""",
    """Accesses\\=({accesses}[^=&]+)""",
    """User\\=(SYSTEM|({user}[^=&]+))""",
    """ComputerName\\=({host}[\w.\-]+)""",
  ]
}
```