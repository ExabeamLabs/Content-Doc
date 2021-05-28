#### Parser Content
```Java
{
Name = json-bro-files-analysis
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "file-read"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """/files.log""",""""fuid\":""", """"conn_uids\":""" ]
  Fields = [
    """"HOST"{1,20}:\s{0,100}"{1,20}({host}[^"]{1,2000})"""",
    """"TAGS"{1,20}:\s{0,100}"{1,20}({event_code}[^"]{1,2000})"""",
    """"ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"tx_hosts\\?"{1,20}:\[\\*"{0,20}({src_ip}[a-fA-F\d.:]{1,2000})\\*"{0,20}\]""",
    """"rx_hosts\\?"{1,20}:\[\\*"{0,20}({dest_ip}[a-fA-F\d.:]{1,2000})\\*"{0,20}\]""",
    """"conn_uids\\?"{1,20}:\[\\{0,25}"{0,20}({conn_uids}[^\]]{1,2000}?)\\{0,25}"{0,20}\]""",
    """"source\\?"{1,20}:\\?"{1,20}({protocol}[^"\\]{1,2000})""",
    """"analyzers\\?"{1,20}:\[({analyzers}.+?)\]""",
    """"mime_type\\?"{1,20}:\\?"{1,20}({mime}[^"\\]{1,2000})""",
    """"filename\\?"{1,20}:\\?"{1,20}({file_path}({file_parent}[^"]{0,2000}?(\\u005c|[\\\/])*)({file_name}[^"\\\/]{1,2000}?(\.({file_ext}[^"\\\/\.]{1,2000}))?))\s{0,100}\\?"""",
    """"seen_bytes\\?"{1,20}:({bytes}\d{1,100})""",
    """"total_bytes\\?"{1,20}:({total_bytes}\d{1,100})""",
    """"md5\\?"{1,20}:\\?"{1,20}({md5}[^"\\]{1,2000})""",
    """"sha1\\?"{1,20}:\\?"{1,20}({sha1}[^"\\]{1,2000})"""
  ]
}
```