#### Parser Content
```Java
{
Name = s-brightmail-email
    Vendor = BrightMail
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """[Brightmail]""", """ A message from """, """ returned Disposition:""" ]
    Fields = [
      """\s({host}[\w\.-]+)\s+bmserver""",
      """A message from\s+<({sender}[^\s@]+@({external_domain_sender}[^\s@>]+))>?\s+source""",
      """source\s+<?({direction}\w+)+>?\s+to""",
      """to\s+<?({recipients}[^<>]+)>?\s+using""",
      """to\s+<?({recipient}[^\s@<]+@({external_domain_recipient}[^\s@>]+))>?\s+using""",
    ]
  }
```