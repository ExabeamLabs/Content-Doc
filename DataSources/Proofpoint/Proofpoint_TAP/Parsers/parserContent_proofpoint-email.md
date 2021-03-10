#### Parser Content
```Java
{
Name = proofpoint-email
    Vendor = Proofpoint
    Product = Proofpoint TAP
    Lms = Direct
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
    Conditions = [ """"subject":""", """"from":""", """"routeDirection":""", """"rcpts":""" ]   
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+(\+|\-)\d\d:\d\d)\s+({host}[^:]+)\s""",
      """"ts":\s*"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+[\+\-]\d+)""",
      """"sizeBytes":\s*({bytes}\d+)""",
      """"from":\s*\[?"({sender}[^"@]+@({external_domain_sender}[^"]+))""",
      """"subject":\s*\["({subject}[^"]+)""",
      """"rcpts":\s*\[({recipients}"({recipient}[^"@]+@({external_domain_recipient}[^"]+)).*?)\]""",
      """"ip":\s*"({dest_ip}[a-fA-F\d.:]+)""",
      """"filter":.*?"disposition":\s*"({outcome}[^"]+)""",
      """"routeDirection":\s*"({direction}[^"]+)""",
      """"message-id":\s*\["({message_id}[^"]+)""",
      """"detectedName":\s*"({attachment}[^"]+)""",
      """"x-originating-ip":\s*\["\[({src_ip}[^"\]]+)""",
      """"host":\s*"\[?({host}[\w\-.]+)\]?"""",
    ]
    DupFields = [ "attachment->attachments" ]
  }
```