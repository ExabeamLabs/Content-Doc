#### Parser Content
```Java
{
Name = proofpoint-email
    Vendor = Proofpoint
    Product = Proofpoint TAP
    Lms = Direct
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
    Conditions = [ """"subject":""", """"from":""", """"rcpts":""", """"rule":""" ]   
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.\-]{1,2000})""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)(\s{1,100}({host}[^:]{1,2000})\s)?""",
      """"ts":\s{0,100}"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}[\+\-]\d{1,100})""",
      """"sizeBytes":\s{0,100}({bytes}\d{1,100})""",
      """"from":\s{0,100}\[?"?({user_fullname}[^"@\s,<>]{1,2000}\s{1,100}[^"@,<>]{1,2000}?)?\s{0,100}\<?({sender}[^"@\s,<>]{1,2000}@({external_domain_sender}[^"@\s,<>]{1,2000}))""",
      """"subject":\s{0,100}\["({subject}[^"]{1,2000}?)\s{0,100}"""",
      """"rcpts":\s{0,100}\["({recipients}({recipient}[^"@]{1,2000}@({external_domain_recipient}[^"]{1,2000})))"\]""",
      """"ip":\s{0,100}"({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """"filter":[^=]+?"disposition":\s{0,100}"({outcome}[^"]{1,2000})""",
      """"routeDirection":\s{0,100}"({direction}[^"]{1,2000})""",
      """"message-id":\s{0,100}\["<*({message_id}[^>"]{1,2000})""",
      """"detectedName":\s{0,100}"({attachment}[^"]{1,2000})""",
      """"ip":\s{0,100}"({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """"x-originating-ip":\s{0,100}\["\[({src_ip}[^"\]]{1,2000})""",
      """"host":\s{0,100}"\[?({host}[\w\-.]{1,2000})\]?"""",
      """"rules":\[[^\]]{0,2000}"rule":"({rule}[^"]{1,2000})""""
    ]
    DupFields = [ "attachment->attachments" ]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "recipient->dlpUser", "sender->emailFrom", "subject->emailSubject", "recipients->emailTo", "outcome->dlpActionTaken","host->dlpDeviceName"]
    NameTemplate = """Proofpoint DLP email ${subject} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```