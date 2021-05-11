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
    """({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm))""",
    """\WComputerName=({host}[\w\-.]+)""",
    """\Wuser="({user}[^"\s]+)""",
    """\Wfrom="({sender}[^"\s@]+@[^"\s@]+)""",
    """\Wsubject="({subject}[^"]+?)\s{0,100}"""",
    """\Wnr_total_recipients=({num_recipients}\d{1,100})""",
    """\Wnr_internal_recipients=({num_internal_recipients}\d{1,100})""",
    """\Wnr_external_recipients=({num_external_recipients}\d{1,100})""",
    """\Wexternal_recipients="({recipients}[^"]*?<?({recipient}[^"\s;,@>']+@({external_domain}[^"\s;,>']+))[^"]*)"""",
    """\Wattachments="(|({attachments}[^"]+))""",
  ]
  DupFields = [ "recipient->external_address" ]
}
```