#### Parser Content
```Java
{
Name = json-bro-files-analysis
  Vendor = Bro
  Lms = Direct
  DataType = "file-read"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """/files.log""",""""fuid\":""", """"conn_uids\":""" ]
  Fields = [
    """"HOST"+:\s*"+({host}[^"]+)"""",
    """"TAGS"+:\s*"+({event_code}[^"]+)"""",
    """"ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"tx_hosts\\?"+:\[\\*"*({src_ip}[a-fA-F\d.:]+)\\*"*\]""",
    """"rx_hosts\\?"+:\[\\*"*({dest_ip}[a-fA-F\d.:]+)\\*"*\]""",
    """"conn_uids\\?"+:\[\\*"*({conn_uids}.+?)\\*"*\]""",
    """"source\\?"+:\\?"+({protocol}[^"\\]+)""",
    """"analyzers\\?"+:\[({analyzers}.+?)\]""",
    """"mime_type\\?"+:\\?"+({mime}[^"\\]+)""",
    """"filename\\?"+:\\?"+({file_path}({file_parent}[^"]*?(\\u005c|[\\\/])*)({file_name}[^"\\\/]+?(\.({file_ext}[^"\\\/\.]+))?))\s*\\?"""",
    """"seen_bytes\\?"+:({bytes}\d+)""",
    """"total_bytes\\?"+:({total_bytes}\d+)""",
    """"md5\\?"+:\\?"+({md5}[^"\\]+)""",
    """"sha1\\?"+:\\?"+({sha1}[^"\\]+)"""
  ]
}
```