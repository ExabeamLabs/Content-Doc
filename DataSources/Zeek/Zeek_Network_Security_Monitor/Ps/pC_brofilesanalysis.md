#### Parser Content
```Java
{
Name = bro-files-analysis
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "file-read"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """files",""",""""fuid":""", """"conn_uids":""" ]
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"_system_name":"({host}[^"]{1,2000})""",
    """"ts":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """"tx_hosts":\["({src_ip}[a-fA-F\d.:]{1,2000})"\]""",
    """"rx_hosts":\["({dest_ip}[a-fA-F\d.:]{1,2000})"\]""",
    """"conn_uids":\["({conn_uids}[^"]{1,2000})"\]""",
    """"source":"({protocol}[^"]{1,2000})""",
    """"analyzers":\[({analyzers}.+?)\]""",
    """"mime_type":"({mime}[^"]{1,2000})""",
    """"seen_bytes":"?({bytes}\d{1,100})""",
    """"total_bytes":({total_bytes}\d{1,100})""",
    """"md5":"({md5}[^"]{1,2000})""",
    """"sha1":"({sha1}[^"]{1,2000})""",
    """"filename":"({file_name}[^"]{1,2000}?(\.({file_ext}\w+))?)"""",
  ]
}
```