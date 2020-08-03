#### Parser Content
```Java
{
Name = airwatch-security-alerts
  DataType = "security-alerts"
  Conditions = [ """AirWatch""", """Event Category:"""", """Event:"""" ]

}

{
  Name = anywhere365-app-activity
  Conditions = [""" CallReceivedOnEndpoint: """]
  Vendor = Anywhere365
  Product = Anywhere365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """\s({log_id}\w+-\w+-\w+-\w+-\w+)\s""",
    """CallReceivedOnEndpoint:\s'sip:({recipient}[^@]+[^\.]+\.[^,\s;']+)""",
  ]
}
```