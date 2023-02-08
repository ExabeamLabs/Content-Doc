#### Parser Content
```Java
{
Name = wdac-security-alert-3089
  Vendor = Microsoft
  Product = Windows Defender Application Control
  Lms = Direct
  DataType = "alert"
  TimeFormat = "EEE MMM dd HH:mm:ss yyyy"
  Conditions = [ """MSWinEventLog""", """Microsoft-Windows-CodeIntegrity""", """3089""", """Signature information for another event""" ]
  Fields = [
    """\s({host}[\w\-.]{1,2000})\s{1,10}MSWinEventLog""",
    """\s({time}\w{3}\s{1,10}\w{3}\s{1,10}\d\d\s{1,10}\d\d:\d\d:\d\d\s{1,10}\d{4})""",
    """({event_code}3089)""",
    """Microsoft-Windows-CodeIntegrity\s{1,10}(N\/A|SYSTEM|LOCAL|NETWORK|({user}[^\s]{1,2000}))\s""",
    """({additional_info}({alert_name}Signature information for another event)\.\s[^<>]{1,2000}\.\s{1,10}({alert_id}\d{1,10}))"""
  ]
  DupFields = [ "host->dest_host" ]


}
```