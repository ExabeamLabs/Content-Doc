#### Parser Content
```Java
{
Name = cef-1102
  Vendor = Microsoft
  Product = Microsoft Windows
  DataType = "windows-audit"
  Lms = Splunk
  TimeFormat = "epoch"
  Conditions = ["""CEF:""", """Microsoft|Microsoft Windows|""", """Microsoft-Windows-Eventlog:1102""", """The audit log was cleared.|""" ]
  Fields = [
    """({event_code}1102)""",
    """\srt=({time}\d{10,13})""",
    """({event_name}The audit log was cleared)""",
    """\sdhost=({dest_host}[\w\.\-]{1,2000})""",
    """\sdst=({dest_ip}[A-Fa-f.:\d]{1,200})""",
    """\Wdntdom=({domain}[^=]{1,2000}?)\s[\w\-\.]{1,2000}=""",
    """\Wduser=({user}[^=]{1,2000}?)\s{0,100}[\w\.\-]{1,2000}=""",
    """dvchost=({host}[\w\.\-]{1,2000})""",
    """cs2=({category}[^=]{1,200}?)\s{0,100}[\w\-\.]{1,2000}="""
  ]


}
```