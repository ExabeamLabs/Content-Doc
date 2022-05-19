#### Parser Content
```Java
{
Name = proofpoint-dlp-email-from
  Vendor = Proofpoint
  Product = Proofpoint TAP/POD
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ" 
  Conditions = [ """msgid""", """"cipher"""", """"pps"""", """"from"""", """:""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"relay"{1,20}:\s{0,100}"{1,20}({host}[\w\-.]{1,2000}?)\.?\s{0,100}\[({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """"from"{1,20}:\s{0,100}\[?"{1,20}([^<,]{1,100}?<|<)?({sender}[^@>,]{1,2000}@[^"\s\>,;]{1,2000})>?\s{0,100}"{1,20}\]?\}{0,2}?,""",
    """"sizeBytes"{1,20}:\s{0,100}"{0,20}({bytes}\d{1,100})""",
    """"nrcpts"{1,20}:\s{0,100}"{1,20}({num_recipients}\d{1,100})""",
    """"proto"{1,20}:\s{0,100}"{1,20}({protocol}[^"]{1,2000})""",
    """"msgid"{1,20}:\s{0,100}"{1,20}<?({message_id}[^>"]{1,2000})""",
    """"ts"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000})""",
    """"cipher"{1,20}:\s{0,100}"{1,20}(NONE|({auth_method}[^"]{1,2000}))""",
    """"qid"{1,20}:\s{0,100}"{1,20}({alert_id}[^"]{1,2000})""",
  ]
  DupFields = ["host->dest_host"]


}
```