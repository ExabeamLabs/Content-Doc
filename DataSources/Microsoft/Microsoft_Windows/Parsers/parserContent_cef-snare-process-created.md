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
    """CEF:([^\|]{0,2000}\|){4}Security:({event_code}\d{1,100})\|({event_name}[^\|]{1,2000})""",
    """\scategoryBehavior=(|({action}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\scategoryOutcome=(|/({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\scategoryObject=(|({object}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sduser=(|({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdproc=(|({process}(({directory}[^=]{0,2000}?)[\\\/]{1,2000})?({process_name}[^=\\\/]{1,2000})))(\s{1,100}\w+=|\s{0,100}$)""",
    """Process ID\\=({process_id}\d{1,100})""",
    """User\\=(-|({user}[^=&]{1,2000}))""",
    """ComputerName\\=({host}[\w.\-]{1,2000})""",
  ]
}
```