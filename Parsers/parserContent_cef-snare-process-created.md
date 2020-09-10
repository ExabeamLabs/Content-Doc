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
    """\srt=({time}\d+)""",
    """CEF:([^\|]*\|){4}Security:({event_code}\d+)\|({event_name}[^\|]+)""",
    """\scategoryBehavior=(|({action}.+?))(\s+\w+=|\s*$)""",
    """\scategoryOutcome=(|/({outcome}.+?))(\s+\w+=|\s*$)""",
    """\scategoryObject=(|({object}.+?))(\s+\w+=|\s*$)""",
    """\sdhost=(|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\sduser=(|({user}.+?))(\s+\w+=|\s*$)""",
    """\sdproc=(|({process}(({directory}[^=]*?)[\\\/]+)?({process_name}[^=\\\/]+)))(\s+\w+=|\s*$)""",
    """Process ID\\=({process_id}\d+)""",
    """User\\=(-|({user}[^=&]+))""",
    """ComputerName\\=({host}[\w.\-]+)""",
  ]
}
```