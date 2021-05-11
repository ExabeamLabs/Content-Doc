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
    """\srt=({time}\d{1,100})""",
    """({event_code}Print)""",
    """\sshost=(([^\/\\=]+)[\/\\]+)?({host}[^=]+?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\ssuser=(({domain}[^\/\\=]+)[\/\\]+)?({user}[^=]+?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\ssproc=({process_name}[^=]+?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\sfsize=({bytes}\d{1,100})\s{1,100}?""",
    """\sad\.DG__Printer=({printer_name}[^=]+?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\sad\.DG__Printer=\\+(.+\|)?({dest_host}\S+?)\\+({printer_name}[^,]+?)\s{0,100}(,.*?)?\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\soldFileName=(|({object}.+?))\s{1,100}(ad\.\S+=|\w+=|$)""",
  ]
  DupFields = [ "host->src_host" ]
}
```