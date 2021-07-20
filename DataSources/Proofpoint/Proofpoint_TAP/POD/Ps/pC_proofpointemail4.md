#### Parser Content
```Java
{
Name = proofpoint-email-4
  Vendor = Proofpoint
  Product = Proofpoint TAP/POD
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"subject"""", """"from"""", """"rcpts"""", """"rule"""", """"to"""", """"message-id"""", """sizeDecodedBytes""", """"url":""", """"helo":""", """"fromHashed":""" ]
  Fields =[
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)""",
    """msgSizeBytes":({bytes}\d{1,2000}),""",
    """from":"({sender}[^@"]{1,2000}@({external_domain_sender}[^"]{1,2000}))"""",
    """subject":\["({subject}[^"]{1,2000}?)\s{0,100}"\]""",
    """rcpts":\[({recipients}"({recipient}[^@"]{1,2000}@({external_domain_recipient}[^"]{1,2000}))"[^\]]{0,2000})\]""",
    """filter":[^\n]{0,30000}?"disposition":"({outcome}[^"]{1,2000})"""",
    """routeDirection":"({direction}[^"]{1,2000})"""",
    """"message-id":\["<({message_id}[^">]{1,2000})>"""",
    """msgParts":[^\n]{0,30000}?"detectedName":"({attachment}[^"]{1,2000})"""",
    """msgParts":[^\n]{0,30000}?"sizeDecodedBytes":({bytes}\d{1,2000}),""",
    """"ip":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """"host":"({host}[^"]{1,2000})"""",
    """"rule":"({rule_name}[^"]{1,2000})"""",
    """fromDisplayNames":\["({user_fullname}[^"]{1,2000})""""
  ]
  DupFields = [ "attachment->attachments" ]
}
```