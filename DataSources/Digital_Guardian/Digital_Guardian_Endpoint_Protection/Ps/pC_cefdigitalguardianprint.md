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
    """\sshost=(([^\/\\=]{1,2000})[\/\\]{1,2000})?({host}[^=]{1,2000}?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\ssuser=(({domain}[^\/\\=]{1,2000})[\/\\]{1,2000})?({user}[^=]{1,2000}?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\ssproc=({process_name}[^=]{1,2000}?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\sfsize=({bytes}\d{1,100})\s{1,100}?""",
    """\sad\.DG__Printer=({printer_name}[^=]{1,2000}?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\sad\.DG__Printer=\\{1,25}([^\|]{1,2000}\|)?({dest_host}\S{1,2000}?)\\{1,25}({printer_name}[^,]{1,2000}?)\s{0,100}(,[^=]{0,2000}?)?\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\soldFileName=(|({object}.+?))\s{1,100}(ad\.\S+=|\w+=|$)""",
  ]
  DupFields = [ "host->src_host" ]
}
```