#### Parser Content
```Java
{
Name = proofpoint-email-6
  Vendor = Proofpoint
  Product = Proofpoint TAP/POD
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"from"""", """"rcpts"""", """"rule"""", """"helo"""", """"actions"""", """"suborgs"""", """"resolveStatus"""" ]
  Fields = [
    """"ts"{1,20}:\s{0,100}"{1,20}({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}[\+\-]\d{1,4})""",
    """"host"{1,20}:\s{0,100}"{1,20}\[?({host}[\w\-.]{1,2000})\]?"""",
    """"from"{1,20}:\s{0,100}"{1,20}({sender}[^"@]{1,2000}@[^"@]{1,2000})"""",
    """"rcpts"{1,20}:\s{0,100}\[({recipients}"{1,20}({recipient}[^"@]{1,2000}@[^"]{1,2000})"{0,20}[^\]]{0,2000}?)\]""",
    """"sizeBytes"{1,20}:\s{0,100}({bytes}\d{1,100})""",	
    """"filter"{1,20}:[^=]{1,3000}?"{1,20}disposition"{1,20}:\s{0,100}"{1,20}({outcome}[^"]{1,2000})""",
    """"ip"{1,20}:\s{0,100}"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"rule"{1,20}:\s{0,100}"{1,20}({rule}[^",]{1,2000})"""",
    """"guid"{0,20}:\s{0,100}"{0,20}({email_id}[^"]{1,2000})"""",
    """"routeDirection"{1,20}:\s{0,100}"{1,20}({direction}[^"]{1,2000})""",
    """"message-id"{1,20}:\s{0,100}\["{1,20}<{0,100}({message_id}[^>"]{1,2000})""",
    """"detectedName"{1,20}:\s{0,100}"{1,20}\s{0,100}({attachment}[^"]{1,2000})"""",
    """"return-path"{1,20}:\s{0,100}\["{1,20}(<>|({return_path}[^"]{1,2000}))""""
  ]


}
```