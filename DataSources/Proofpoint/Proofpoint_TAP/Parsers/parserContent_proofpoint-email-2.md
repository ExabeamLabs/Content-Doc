#### Parser Content
```Java
{
Name = proofpoint-email-2
   Vendor = Proofpoint
   Product = Proofpoint TAP
   Lms = Direct
   DataType = "dlp-email-alert"
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
   Conditions = [  """'subject':""",   """'from':""",   """'routeDirection':""",       """'rcpts':"""    ]
   Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)\s{1,100}({host}[^:]+)\s""",
      """'startTime':\s{0,100}'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d{1,100})""",
      """'sizeBytes':\s{0,100}({bytes}\d{1,100})""",
      """'from':\s{0,100}\[?'[^@]*?({sender}[^'@"\s=<\[\]]+@({external_domain_sender}[^'@"\s=>\[\]]+))""",
      """'subject':\s{0,100}\['\s{0,100}({subject}.+?)\s{0,100}'""",
      """'envelope':\s{0,100}\{.*'rcpts':\s{0,100}\['({recipients}({recipient}[^'@]+@({external_domain_recipient}[^']+)).*?)'\]""",
      """'ip':\s{0,100}'({dest_ip}[a-fA-F\d.:]+)""",
      """'filter'.*?'action':\s{0,100}'({outcome}[^']+)'.*?'isFinal':\s{0,100}True""",
      """'filter'.*'isFinal':\s{0,100}True,\s{0,100}.*'action':\s{0,100}'({outcome}[^']+)'""",
      """'rule':\s{0,100}'({rule_name}[^']+)'""",
      """'isMsgReinjected':\s{0,100}({is_consolidated}\w+),""",
      """'connection':\s{0,100}\{.*'country':\s{0,100}'({country}[^']+)'""",
      """'appname':\s{0,100}'\s{0,100}({app_name}.+?)\s{0,100}'""",
      """'creator':\s{0,100}'\s{0,100}({creator}.+?)\s{0,100}'""",
      """'pagecount':\s{0,100}({page_count}\d{1,100})""",
      """'folder':\s{0,100}'(?:({folder}[^']+))""",
      """'routeDirection':\s{0,100}'({direction}[^']+)""",
      """'message-id':\s{0,100}\['({message_id}[^']+)""",
      """'detectedName':\s{0,100}'({attachment}[^']+)""",
      """'x-originating-ip':\s{0,100}\['\[({src_ip}[A-Fa-f:\d.]+)""",
      """'host':\s{0,100}'\[?({host}[\w\-.]+)"""
   ]
    DupFields = ["attachment->attachments"]
 }
```