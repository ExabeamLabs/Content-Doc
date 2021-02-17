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
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+(\+|\-)\d\d:\d\d)\s+({host}[^:]+)\s""",
      """'startTime':\s*'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+(\+|\-)\d+)""",
      """'sizeBytes':\s*({bytes}\d+)""",
      """'from':\s*\[?'[^@]*?({sender}[^'@"\s=<\[\]]+@({external_domain_sender}[^'@"\s=>\[\]]+))""",
      """'subject':\s*\['\s*({subject}.+?)\s*'""",
      """'envelope':\s*\{.*'rcpts':\s*\['({recipients}({recipient}[^'@]+@({external_domain_recipient}[^']+)).*?)'\]""",
      """'ip':\s*'({dest_ip}[a-fA-F\d.:]+)""",
      """'filter'.*?'action':\s*'({outcome}[^']+)'.*?'isFinal':\s*True""",
      """'filter'.*'isFinal':\s*True,\s*.*'action':\s*'({outcome}[^']+)'""",
      """'rule':\s*'({rule_name}[^']+)'""",
      """'isMsgReinjected':\s*({is_consolidated}\w+),""",
      """'connection':\s*\{.*'country':\s*'({country}[^']+)'""",
      """'appname':\s*'\s*({app_name}.+?)\s*'""",
      """'creator':\s*'\s*({creator}.+?)\s*'""",
      """'pagecount':\s*({page_count}\d+)""",
      """'folder':\s*'(?:({folder}[^']+))""",
      """'routeDirection':\s*'({direction}[^']+)""",
      """'message-id':\s*\['({message_id}[^']+)""",
      """'detectedName':\s*'({attachment}[^']+)""",
      """'x-originating-ip':\s*\['\[({src_ip}[A-Fa-f:\d.]+)""",
      """'host':\s*'\[?({host}[\w\-.]+)"""
   ]
    DupFields = ["attachment->attachments"]
 }
```