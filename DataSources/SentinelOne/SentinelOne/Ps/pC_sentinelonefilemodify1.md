#### Parser Content
```Java
{
Name = sentinelone-file-modify-1
  DataType = "file-write"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """fileModification {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}fileModification)""",
    """type"{1,20}:"{1,20}file"{1,20
sentinelone-activity {
    Vendor = SentinelOne
    Product = SentinelOne
    Lms = Splunk
    TimeFormat = "epoch"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S{1,2000})""",
      """\smillisecondsSinceEpoch:\s{0,100}({time}\d{1,20})""",
      """\\ncomputer_name:\s{0,100}"{1,20}({host}[^"]{1,2000})"""
      """\\nos_name:\s{0,100}"{1,20}({os}[^"]{1,2000})"""
      """\\nagent_version:\s{0,100}"{1,20}({user_agent}[^"]{1,2000})"""
      """\ssizeBytes:\s{0,100}({bytes}\d{1,100})""",
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
      """sha1:\s{0,100}"{0,100}({sha1}[^"]{1,2000})""""
    
}
```