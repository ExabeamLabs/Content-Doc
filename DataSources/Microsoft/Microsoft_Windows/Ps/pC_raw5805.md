#### Parser Content
```Java
{
Name = raw-5805
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-failed-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = ["""NETLOGON""" , """The session setup from the computer""", """5805</EventID>""" ]
  Fields = [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """<EventID Qualifiers='0'>({event_code}5805)<\/EventID>""",
    """<Computer>({host}[^<]{1,2000})<\/Computer>""",
    """<Message>({additional_info}[^<]{1,2000})<\/Message>""",
    """ComputerName(:|=)\s{0,100}({host}[\w.-]{1,2000})""",
    """Event ID: ({event_code}\d{1,100})""",
    """({event_name}The session setup from the computer ({src_host}[^\s]{1,2000})\sfailed to authenticate)""",
    """The following error occurred:\s{1,100}({failure_reason}[^<]{1,2000})\.<\/Message>"""
  ]


}
```