#### Parser Content
```Java
{
Name = raw-4723
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-password-change"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ "An attempt was made to change" ]
    Fields = [
      """({event_name}An attempt was made to change an account's password)""",
      """exabeam_host=({host}[\w.\-]+)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """\Wrt=({time}\d+)""",
      """Security,(rn=)?({record_id}[\d]+)""",
      """({host}[\w.\-]+)\s*:\s+An attempt was made to change""",
      """\scategoryOutcome=(|/({outcome}.+?))(\s+\w+=|\s*$)""",
      """({outcome}((Success|Failure|Audit)\s+\w+)|Information)(\s+|\s*,\s*|#011)({host}[\w\.\-]+)""",  
      """"TimeGenerated":"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)""",
      """"Computer":"({host}[\w\-.]+)""",	  
      """EvntSLog:\s*\[({outcome}.+?)\]""",
      """;\s+Type = "({outcome}[^"]+)"""",
      """Keywords=({outcome}.+?)\s+\w+=""",
      """Event Type : ({outcome}.+?)\.\s+Log Type :""",
      """exabeam_qidName=({outcome}[^:=]+?)\s+\w+=""",
      """\Wact=({outcome}.+?)\s+(\w+=|$)""",
      """({host}[^\/\s]+)\/Microsoft-Windows-Security-Auditing""",
      """Computer(\w+)?["\s]*(:|=)\s*"?({host}.+?)("|\s)""",
      """Computer\s+:\s+({host}[\w\-]+)""",
      """({event_code}4723)""",
      """Subject.+?Security ID:\s+({user_sid}.+?)\s+Account Name""",
      """Subject.+?Account Name:\s+({user}.+?)\s+Account Domain""",
      """Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
      """Target Account.+?Security ID:\s+({target_user_sid}.+?)\s+Account Name:""",
      """Target Account.+?Account Name:\s+({target_user}.+?)\s+Account Domain:\s+({target_domain}.+?)\s+Additional""",
      """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
      """\Wsntdom=({domain}.+?)\s+(\w+=|$)""",
      """\Wshost=({src_host}.+?)\s+(\w+=|$)""",
      """\Wduser=(({domain}[^\\=]+)\\+)?({target_user}[^\s\\=]+)""",
      """\Wsuser=(({domain}[^\\=]+)\\+)?({user}[^\s\\=]+)""",
      """"Account":"(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+)""",
      """"TargetAccount":"(({target_domain}[^\\\s"]+)\\+)?({target_user}[^\\\s"]+)""",
      """"SubjectUserSid":"({user_sid}[^\s"]+)""",
      """"SubjectLogonId":"({logon_id}[^\s"]+)""",
      """"TargetSid":"({target_user_sid}[^\s"]+)""",
      ]
    DupFields = [ "host->dest_host" ]
  }
```