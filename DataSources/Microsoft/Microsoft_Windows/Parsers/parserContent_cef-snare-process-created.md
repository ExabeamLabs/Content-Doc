#### Parser Content
```Java
{
Name = cef-snare-process-created
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = ArcSight
  DataType = "process-created"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Snare|""", """|A new process has been created|""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """CEF:([^\|]*\|){4}Security:({event_code}\d{1,100})\|({event_name}[^\|]+)""",
    """\scategoryBehavior=(|({action}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\scategoryOutcome=(|/({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\scategoryObject=(|({object}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\sduser=(|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdproc=(|({process}(({directory}[^=]*?)[\\\/]+)?({process_name}[^=\\\/]+)))(\s{1,100}\w+=|\s{0,100}$)""",
    """Process ID\\=({process_id}\d{1,100})""",
    """User\\=(-|({user}[^=&]+))""",
    """ComputerName\\=({host}[\w.\-]+)""",
  ]
}
```