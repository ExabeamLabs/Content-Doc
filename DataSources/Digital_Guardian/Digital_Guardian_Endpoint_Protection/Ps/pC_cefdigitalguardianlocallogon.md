#### Parser Content
```Java
{
Name = cef-digitalguardian-local-logon
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = ArcSight
  DataType = "local-logon"
  TimeFormat = "epoch"
  Conditions = [ """|Digital Guardian|Digital Guardian|""", """|User Logon|""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sshost=(([^\/\\=]{1,2000})[\/\\]{1,2000})?({host}\S+)""",
    """\ssuser=(({domain}[^\/\\=]{1,2000})[\/\\]{1,2000})?({user}[^=]{1,2000}?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\ssproc=({process_name}.+?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """({event_code}User Logon)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```