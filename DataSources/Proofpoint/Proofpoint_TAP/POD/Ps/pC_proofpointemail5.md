#### Parser Content
```Java
{
Name = proofpoint-email-5
    Vendor = Proofpoint
    Product = Proofpoint TAP/POD
    Lms = Direct
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
    Conditions = [ """CEF""", """cipher""", """"from"""", """:""", """"to"""", """"pps":""", """msgid""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.\-]{1,2000})""",
      """"ts"{1,20}:\s{0,100}"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}[\+\-]\d{1,100})""",
      """"sizeBytes"{1,20}:\s{0,100}({bytes}\d{1,100})""",
      """"from"{1,20}:\s{0,100}\[?"{1,20}?({user_fullname}[^"@\s,<>]{1,2000}\s{1,100}[^"@,<>]{1,2000}?)?\s{0,100}\<?({sender}[^"@\s,<>]{1,2000}@({external_domain_sender}[^"@\s,<>]{1,2000}))""",
      """"subject"{1,20}:\s{0,100}\["{1,20}({subject}[^"]{1,2000}?)\s{0,100}"""",
      """"rcpts"{1,20}:\s{0,100}\["{1,20}({recipients}({recipient}[^"@]{1,2000}@({external_domain_recipient}[^"]{1,2000}))[^\]]{0,2000}?)"{0,20}\]""",
      """"routeDirection"{1,20}:\s{0,100}"{1,20}({direction}[^"]{1,2000})""",
      """"msgid"{1,20}:\s{0,100}"{1,20}<?({message_id}[^>"]{1,2000})""",
      """"detectedName"{1,20}:\s{0,100}"{1,20}\s{0,100}({attachment}[^"]{1,2000})"{1,20},"{1,20}md5""",
      """"ip"{1,20}:\s{0,100}"{1,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """"host"{1,20}:\s{0,100}"{1,20}\[?({host}[\w\-.]{1,2000})\]?"""",
      """"rules"{1,20}:\[[^\]]{0,2000}"{1,20}rule"{1,20}:"{1,20}({rule}[^"]{1,2000})"""",
      """"filter"{1,20}:.*?"{1,20}disposition"{1,20}:\s{0,100}"{1,20}({outcome}[^"]{1,2000})""",
      """"return-path"{1,20}:\["{1,20}(<>|({return_path}[^"\],]{1,2000}))"""
    ]
  }
```