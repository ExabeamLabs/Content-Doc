#### Parser Content
```Java
{
Name = cef-digitalguardian-print
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = ArcSight
  DataType = "print-activity"
  TimeFormat = "epoch"
  Conditions = [ """|Digital Guardian|Digital Guardian|""", """|Print|""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """({event_code}Print)""",
    """\sshost=(([^\/\\=]+)[\/\\]+)?({host}[^=]+?)\s+(ad\.\S+=|\w+=|$)""",
    """\ssuser=(({domain}[^\/\\=]+)[\/\\]+)?({user}[^=]+?)\s+(ad\.\S+=|\w+=|$)""",
    """\ssproc=({process_name}[^=]+?)\s+(ad\.\S+=|\w+=|$)""",
    """\sfsize=({bytes}\d+)\s+?""",
    """\sad\.DG__Printer=({printer_name}[^=]+?)\s+(ad\.\S+=|\w+=|$)""",
    """\sad\.DG__Printer=\\+(.+\|)?({dest_host}\S+?)\\+({printer_name}[^,]+?)\s*(,.*?)?\s+(ad\.\S+=|\w+=|$)""",
    """\soldFileName=(|({object}.+?))\s+(ad\.\S+=|\w+=|$)""",
  ]
  DupFields = [ "host->src_host" ]
}
```