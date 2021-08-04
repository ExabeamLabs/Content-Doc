#### Parser Content
```Java
{
Name = s-brightmail-email
    Vendor = Symantec
    Product = Symantec Brightmail
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "epoch_sec"
    Conditions = [ """[Brightmail]""", """ A message from """, """ returned Disposition:""" ]
    Fields = [
      """\s({host}[\w\.-]{1,2000})\s{1,100}bmserver""",
      """A message from\s{1,100}<({sender}[^\s@]{1,2000}@({external_domain_sender}[^\s@>]{1,2000}))>?\s{1,100}source""",
      """source\s{1,100}<?({direction}\w+)+>?\s{1,100}to""",
      """to\s{1,100}<?({recipients}[^<>]{1,2000})>?\s{1,100}using""",
      """to\s{1,100}<?({recipient}[^\s@<]{1,2000}@({external_domain_recipient}[^\s@>]{1,2000}))>?\s{1,100}using""",
    ]
  }
```