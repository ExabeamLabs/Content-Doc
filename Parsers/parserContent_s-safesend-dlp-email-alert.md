#### Parser Content
```Java
{
Name = s-safesend-dlp-email-alert
  Vendor = SafeSend
  Product = SafeSend
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """action=email_external""", """external_recipients="""" ]
  Fields = [
    """({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(AM|PM|am|pm))""",
    """\WComputerName=({host}[\w\-.]+)""",
    """\Wuser="({user}[^"\s]+)""",
    """\Wfrom="({sender}[^"\s@]+@[^"\s@]+)""",
    """\Wsubject="({subject}[^"]+?)\s*"""",
    """\Wnr_total_recipients=({num_recipients}\d+)""",
    """\Wnr_internal_recipients=({num_internal_recipients}\d+)""",
    """\Wnr_external_recipients=({num_external_recipients}\d+)""",
    """\Wexternal_recipients="({recipients}[^"]*?<?({recipient}[^"\s;,@>']+@({external_domain}[^"\s;,>']+))[^"]*)"""",
    """\Wattachments="(|({attachments}[^"]+))""",
  ]
  DupFields = [ "recipient->external_address" ]
}
```