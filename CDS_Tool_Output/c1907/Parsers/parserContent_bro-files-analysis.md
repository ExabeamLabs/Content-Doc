#### Parser Content
```Java
{
Name = bro-files-analysis
  Vendor = Bro
  Lms = Direct
  DataType = "file-read"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """files",""",""""fuid":""", """"conn_uids":""" ]
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"ts":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """"tx_hosts":\["({src_ip}[a-fA-F\d.:]+)"\]""",
    """"rx_hosts":\["({dest_ip}[a-fA-F\d.:]+)"\]""",
    """"conn_uids":\["({conn_uids}[^"]+)"\]""",
    """"source":"({protocol}[^"]+)""",
    """"analyzers":\[({analyzers}.+?)\]""",
    """"mime_type":"({mime}[^"]+)""",
    """"seen_bytes":"?({bytes}\d+)""",
    """"total_bytes":({total_bytes}\d+)""",
    """"md5":"({md5}[^"]+)""",
    """"sha1":"({sha1}[^"]+)""",
    """"filename":"({file_name}[^"]+?(\.({file_ext}\w+))?)"""",
  ]
}
```