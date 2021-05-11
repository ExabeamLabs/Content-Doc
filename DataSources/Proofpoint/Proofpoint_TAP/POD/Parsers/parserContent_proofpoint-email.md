#### Parser Content
```Java
{
Name = proofpoint-email
    Vendor = Proofpoint
    Product = Proofpoint TAP/POD
    Lms = Direct
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
    Conditions = [ """"subject"""", """"from"""", """"rcpts"""", """"rule"""", """:""" ]   
    Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w.\-]+)""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)(\s{1,100}({host}[^:]+)\s)?""",
      """"ts"{1,20}:\s{0,100}"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}[\+\-]\d{1,100})""",
      """"sizeBytes"{1,20}:\s{0,100}({bytes}\d{1,100})""",
      """"from"{1,20}:\s{0,100}\[?"{1,20}?({user_fullname}[^"@\s,<>]+\s{1,100}[^"@,<>]+?)?\s{0,100}\<?({sender}[^"@\s,<>]+@({external_domain_sender}[^"@\s,<>]+))""",
      """"subject"{1,20}:\s{0,100}\["{1,20}({subject}[^"]+?)\s{0,100}"""",
      """"rcpts"{1,20}:\s{0,100}\["{1,20}({recipients}({recipient}[^"@]+@({external_domain_recipient}[^"]+))[^\]]*?)"{0,20}\]""",
      """"ip"{1,20}:\s{0,100}"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
      """"filter"{1,20}:[^=]+?"{1,20}disposition"{1,20}:\s{0,100}"{1,20}({outcome}[^"]+)""",
      """"routeDirection"{1,20}:\s{0,100}"{1,20}({direction}[^"]+)""",
      """"message-id"{1,20}:\s{0,100}\["{1,20}<*({message_id}[^>"]+)""",
      """msgParts.+"detectedName"{1,20}:\s{0,100}"{1,20}\s{0,100}({attachment}[^"]+)""",
      """msgParts.+"sizeDecodedBytes":\s{0,99}({bytes}\d{1,100})""",
      """"ip"{1,20}:\s{0,100}"{1,20}({src_ip}[A-Fa-f:\d.]+)""",
      """"x-originating-ip"{1,20}:\s{0,100}\["{1,20}\[({src_ip}[^"\]]+)""",
      """"host"{1,20}:\s{0,100}"{1,20}\[?({host}[\w\-.]+)\]?"""",
      """"rules"{1,20}:\[[^\]]*"{1,20}rule"{1,20}:"{1,20}({rule}[^"]+)""""
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