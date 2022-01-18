#### Parser Content
```Java
{
Name = sentinelone-dns-response-1
  DataType = "dns-response"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """dns {""","""results:""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}dns)""",
    """query:\s{0,100}\\?"{1,20}({query}[^"]{1,2000}?)\.?\\?"""",
    """results:\s{0,100}\\?"{1,20}({response}[^"]{1,2000}?)\\?""""
  ]

sentinelone-activity {
    Vendor = SentinelOne
    Product = SentinelOne
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\s{0,100}[^\s]{1,2000}\s{0,100}Skyformation""",
      """\ssizeBytes:\s{0,100}({bytes}\d{1,100})""",
      """\smsg=({additional_info}[^=]{1,2000}?)\s{0,100}\w+=""",
      """\sproto=({protocol}[^=]{1,2000}?)\s{0,100}\w+=""",
      """\srequestClientApplication=[^@]{1,2000}@({web_domain}[^=]{1,2000}?)\s{0,100}\w+=""",
      """user\s{0,100}\{[^\}]{1,2000}?sid:[^"]{0,2000}?"{1,20}({user_sid}[^"\\]{1,2000})""",
      """user\s{0,100}\{\\n\s{1,100}name:\s{1,100}\\?"{0,20}((NT AUTHORITY|({domain}[^\\"]{1,2000}))\\+)?(SYSTEM|NETWORK SERVICE|LOCAL SERVICE|({user}[^\\"]{1,2000}))""",
      """"app-username":"((NT AUTHORITY|({domain}[^\\"]{1,2000}))\\+)?(SYSTEM|NETWORK SERVICE|LOCAL SERVICE|({user}[^"]{1,2000}?))\s{0,100}"""",
      """\ssha256:\s{0,100}\\?"{1,20}({sha256}[^"\\]{1,2000})""",
      """\smd5:\s{0,100}\\?"{1,20}({md5}[^"\\]{1,2000})""",
      """\spid:\s{0,100}({pid}\d{1,100})""",
      """\ssource.*?node.+?value:\s{0,100}\\?"{1,20}({src_host}[^"\\]{1,2000})""",
      """path:\s{1,100}\\?"{1,20}({process}({process_directory}[^"]{1,2000}?)[\\\/]{0,2000}({process_name}[^"\\\/]{1,2000}))\\*"""",
      """destinationAddress\s.*?address:\s{0,100}\\?"{1,20}({dest_ip}[^\\"]{1,2000})""",
      """destinationAddress\s.*?port:\s{0,100}({dest_port}\d{1,100})""",
      """\sstatus:\s{0,100}({outcome}\w+)""",
      """sourceAddress\s.*?port:\s{0,100}({src_port}\d{1,100})""",
      """sourceAddress\s.*?address:\s{0,100}\\?"{1,20}({src_ip}[^"\\]{1,2000})""",
      """fileType=({activity_type}[^=]{1,2000}?)\s{0,100}\w+="""
    
}
```