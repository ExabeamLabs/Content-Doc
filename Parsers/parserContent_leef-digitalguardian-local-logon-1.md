#### Parser Content
```Java
{
Name = leef-digitalguardian-local-logon-1
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|23|""" ]
}

{
  Name = cef-digitalguardian-local-logon
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = ArcSight
  DataType = "local-logon"
  TimeFormat = "epoch"
  Conditions = [ """|Digital Guardian|Digital Guardian|""", """|User Logon|""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sshost=(([^\/\\=]+)[\/\\]+)?({host}\S+)""",
    """\ssuser=(({domain}[^\/\\=]+)[\/\\]+)?({user}[^=]+?)\s+(ad\.\S+=|\w+=|$)""",
    """\ssproc=({process_name}.+?)\s+(ad\.\S+=|\w+=|$)""",
    """({event_code}User Logon)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```