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
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)\s{1,100}({host}[^:]{1,2000})\s""",
      """'startTime':\s{0,100}'({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d{1,100})""",
      """'sizeBytes':\s{0,100}({bytes}\d{1,100})""",
      """'from':\s{0,100}\[?'[^@]{0,2000}?({sender}[^'@"\s=<\[\]]{1,2000}@[^'@"\s=>\[\]]{1,2000})""",
      """'subject':\s{0,100}\['\s{0,100}({subject}.+?)\s{0,100}'""",
      """'envelope':\s{0,100}\{.*'rcpts':\s{0,100}\['({recipients}({recipient}[^'@]{1,2000}@[^']{1,2000}).*?)'\]""",
      """'ip':\s{0,100}'({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """'filter'.*?'action':\s{0,100}'({outcome}[^']{1,2000})'.*?'isFinal':\s{0,100}True""",
      """'filter'.*'isFinal':\s{0,100}True,\s{0,100}.*'action':\s{0,100}'({outcome}[^']{1,2000})'""",
      """'rule':\s{0,100}'({rule_name}[^']{1,2000})'""",
      """'isMsgReinjected':\s{0,100}({is_consolidated}\w+),""",
      """'connection':\s{0,100}\{.*'country':\s{0,100}'({country}[^']{1,2000})'""",
      """'appname':\s{0,100}'\s{0,100}({app_name}.+?)\s{0,100}'""",
      """'creator':\s{0,100}'\s{0,100}({creator}.+?)\s{0,100}'""",
      """'pagecount':\s{0,100}({page_count}\d{1,100})""",
      """'folder':\s{0,100}'(?:({folder}[^']{1,2000}))""",
      """'routeDirection':\s{0,100}'({direction}[^']{1,2000})""",
      """'message-id':\s{0,100}\['({message_id}[^']{1,2000})""",
      """'detectedName':\s{0,100}'({attachment}[^']{1,2000})""",
      """'x-originating-ip':\s{0,100}\['\[({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """'host':\s{0,100}'\[?({host}[\w\-.]{1,2000})"""
   ]
    DupFields = ["attachment->attachments"]
 

}
```