#### Parser Content
```Java
{
Name = proofpoint-dlp-email-to
  Vendor = Proofpoint
  Product = Proofpoint TAP/POD
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """stat""", """"cipher"""", """"pps"""", """"to"""", """:""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"relay"{1,20}:\s{0,100}"{1,20}({host}[\w\-.]{1,2000}?)\.?\s{0,100}\[({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """"to"{1,20}:\s{0,100}\["{1,20}({recipients}<?({recipient}[^@]{1,2000}@[^\s\>;"]{1,2000}))"{1,20}\]\}""",
    """"sizeBytes"{1,20}:\s{0,100}"{0,20}({bytes}\d{1,100})""",
    """"ts"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000})""",
    """"cipher"{1,20}:\s{0,100}"{1,20}(NONE|({auth_method}[^"]{1,2000}))""",
    """"qid"{1,20}:\s{0,100}"{1,20}({alert_id}[^"]{1,2000})""",
    """"dsn"{1,20}:\s{0,100}"{1,20}({outcome}[^"]{1,2000})""",
    """"stat"{1,20}:\s{0,100}"{1,20}({action}(Sent|Deferred|User unknown|queued))""",
    """"return-path":\["(<>|({return_path}[^"]{1,2000}))""""
  ]
  DupFields = ["host->dest_host"]
}
```