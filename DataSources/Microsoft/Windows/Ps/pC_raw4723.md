#### Parser Content
```Java
{
Name = raw-4723
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-password-change"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ "An attempt was made to change" ]
    Fields = [
      """({event_name}An attempt was made to change an account's password)""",
      """"agent_hostname":"({host}[^"]{1,200})"""",
      """exabeam_host=(gcs-topic|({host}[\w.\-]{1,2000}))""",
      """EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
      """timestamp"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\+\d\d\d\d)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """\Wrt=({time}\d{1,100})""",
      """Security,(rn=)?({record_id}[\d]{1,2000})""",
      """({host}[\w.\-]{1,2000})\s{0,100}:\s{1,100}An attempt was made to change""",
      """\scategoryOutcome=(|/({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """({outcome}((Success|Failure|Audit)\s{1,100}\w+)|Information)(\s{1,100}|\s{0,100},\s{0,100}|#011)({host}[\w\.\-]{1,2000})""",  
      """"TimeGenerated":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
      """"(?i)Computer":"({host}[\w\-.]{1,2000})""",	  
      """EvntSLog:\s{0,100}\[({outcome}.+?)\]""",
      """;\s{1,100}Type = "({outcome}[^"]{1,2000})"""",
      """Keywords=({outcome}.+?)\s{1,100}\w+=""",
      """Event Type : ({outcome}.+?)\.\s{1,100}Log Type :""",
      """exabeam_qidName=({outcome}[^:=]{1,2000}?)\s{1,100}\w+=""",
      """\Wact=({outcome}.+?)\s{1,100}(\w+=|$)""",
      """({host}[^\/\s]{1,2000})\/Microsoft-Windows-Security-Auditing""",
      """Computer(\w+)?["\s]{0,2000}(:|=)\s{0,100}"?({host}.+?)("|\s)""",
      """Computer\s{1,100}:\s{1,100}({host}[\w\-]{1,2000})""",
      """({event_code}4723)""",
      """Subject.+?Security ID:\s{1,100}({user_sid}[^:]{1,2000}?)\s{1,100}Account Name""",
      """Subject.+?Account Name:\s{1,100}({user}[^:]{1,2000}?)\s{1,100}Account Domain""",
      """Account Domain:\s{1,100}({domain}[^:]{1,2000}?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
      """Target Account.+?Security ID:\s{1,100}({target_user_sid}[^:]{1,2000}?)\s{1,100}Account Name:""",
      """Target Account.+?Account Name:\s{1,100}({target_user}[^:]{1,2000}?)\s{1,100}Account Domain:\s{1,100}({target_domain}[^:]{1,2000}?)\s{1,100}Additional""",
      """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """\Wsntdom=({domain}.+?)\s{1,100}(\w+=|$)""",
      """\Wshost=({src_host}.+?)\s{1,100}(\w+=|$)""",
      """\Wduser=(({domain}[^\\=]{1,2000})\\+)?({target_user}[^\s\\=]{1,2000})""",
      """\Wsuser=(({domain}[^\\=]{1,2000})\\+)?({user}[^\s\\=]{1,2000})""",
      """"Account":"(({domain}[^\\\s"]{1,2000})\\+)?({user}[^\\\s"]{1,2000})""",
      """"TargetAccount":"(({target_domain}[^\\\s"]{1,2000})\\+)?({target_user}[^\\\s"]{1,2000})""",
      """"SubjectUserSid":"({user_sid}[^\s"]{1,2000})""",
      """"SubjectLogonId":"({logon_id}[^\s"]{1,2000})""",
      """"TargetSid":"({target_user_sid}[^\s"]{1,2000})""",
      ]
    DupFields = [ "host->dest_host" ]
  }
```