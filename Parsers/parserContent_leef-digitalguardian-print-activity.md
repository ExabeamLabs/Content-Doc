#### Parser Content
```Java
{
Name = leef-digitalguardian-print-activity
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = QRadar
  DataType = "print-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|Print|""" ]
}

${DGParserTemplates.leef-digitalguardian-print-activity} {
  Name = leef-digitalguardian-print-activity-1
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|22|""" ]
}

${DGParserTemplates.leef-digitalguardian-dlp-email-alert-out} {
  Name = leef-digitalguardian-dlp-email-alert-out
  Vendor = Digital Guardian
  Product = Network DLP
  Lms = QRadar
  DataType = "dlp-email-alert"
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|Send Mail|""" ]
}

${DGParserTemplates.leef-digitalguardian-dlp-email-alert-out} {
  Name = leef-digitalguardian-dlp-email-alert-out-1
  DataType = "dlp-email-alert"
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|28|""" ]
}

${DGParserTemplates.leef-digitalguardian-local-logon} {
  Name = leef-digitalguardian-local-logon
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = QRadar
  DataType = "local-logon"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|User Logon|""" ]
}

${DGParserTemplates.leef-digitalguardian-local-logon} {
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