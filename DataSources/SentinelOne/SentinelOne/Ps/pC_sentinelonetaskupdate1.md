#### Parser Content
```Java
{
Name = sentinelone-task-update-1
  DataType = "windows-task-created"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """schedTaskUpdate {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}schedTaskUpdate)""",
    """commandLine:\s{0,100}\\?["\\]{0,2000}"{1,20}({command_line}[^"]{1,2000}?)\\*"""",
    """taskName:\s{0,100}\\?"{1,20}\\*({task_name}[^"]{1,2000}?)\\*""""
  ]
  DupFields = ["host->dest_host"]

sentinelone-activity {
    Vendor = SentinelOne
    Product = SentinelOne
    Lms = Splunk
    TimeFormat = "epoch"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """\smillisecondsSinceEpoch:\s{0,100}({time}\d+)""",
      """\\ncomputer_name:\s{0,100}"{1,20}({host}[^"]{1,2000})"""
      """\\nos_name:\s{0,100}"{1,20}({os}[^"]{1,2000})"""
      """\\nagent_version:\s{0,100}"{1,20}({user_agent}[^"]{1,2000})"""
      """\ssizeBytes:\s{0,100}({bytes}\d{1,100})""",
      """\smsg=({additional_info}[^=]{1,2000}?)\s{0,100}\w+=""",
      """\srequestClientApplication=[^@]{1,2000}@({web_domain}[^=]{1,2000}?)\s{0,100}\w+=""",
      """user\s{0,100}\{[^\}]{1,2000}?sid:[^"]{0,2000}?"{1,20}({user_sid}[^"\\]{1,2000})""",
      """user\s{0,100}\{\\n\s{1,100}name:\s{1,100}\\?"{0,20}((NT AUTHORITY|({domain}[^\\"]{1,2000}))\\+)?(SYSTEM|NETWORK SERVICE|LOCAL SERVICE|({user}[^\\"]{1,2000}))""",
      """"app-username":"((NT AUTHORITY|({domain}[^\\"]{1,2000}))\\+)?(SYSTEM|NETWORK SERVICE|LOCAL SERVICE|({user}[^"]{1,2000}?))\s{0,100}"""",
      """\ssha256:\s{0,100}\\?"{1,20}({sha256}[^"\\]{1,2000})""",
      """\smd5:\s{0,100}\\?"{1,20}({md5}[^"\\]{1,2000})""",
      """\spid:\s{0,100}({pid}\d{1,100})""",
      """path:\s{1,100}\\?"{1,20}({process}({process_directory}[^"]{1,2000}?)[\\\/]{0,2000}({process_name}[^"\\\/]{1,2000}))\\*"""",
      """destinationAddress\s.*?address:\s{0,100}\\?"{1,20}({dest_ip}[^\\"]{1,2000})""",
      """destinationAddress\s.*?port:\s{0,100}({dest_port}\d{1,100})""",
      """\sstatus:\s{0,100}({outcome}\w+)""",
      """sourceAddress\s.*?port:\s{0,100}({src_port}\d{1,100})""",
      """sourceAddress\s.*?address:\s{0,100}\\?"{1,20}({src_ip}[^"\\]{1,2000})""",
      """fileType=({activity_type}[^=]{1,2000}?)\s{0,100}\w+="""
    
}
```