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
      """exabeam_host=([^=]+@\s*)?({host}[\w.\-]+)""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+(\+|\-)\d\d:\d\d)(\s+({host}[^:]+)\s)?""",
      """"ts":\s*"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+[\+\-]\d+)""",
      """"sizeBytes":\s*({bytes}\d+)""",
      """"from":\s*\[?"?({user_fullname}[^"@\s,<>]+\s+[^"@,<>]+?)?\s*\<?({sender}[^"@\s,<>]+@({external_domain_sender}[^"@\s,<>]+))""",
      """"subject":\s*\["({subject}[^"]+)""",
      """"rcpts":\s*\["({recipients}({recipient}[^"@]+@({external_domain_recipient}[^"]+)))"\]""",
      """"ip":\s*"({dest_ip}[a-fA-F\d.:]+)""",
      """"filter":[^=]+?"disposition":\s*"({outcome}[^"]+)""",
      """"routeDirection":\s*"({direction}[^"]+)""",
      """"message-id":\s*\["<*({message_id}[^>"]+)""",
      """"detectedName":\s*"({attachment}[^"]+)""",
      """"ip":\s*"({src_ip}[A-Fa-f:\d.]+)""",
      """"x-originating-ip":\s*\["\[({src_ip}[^"\]]+)""",
      """"host":\s*"\[?({host}[\w\-.]+)\]?"""",
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