#### Parser Content
```Java
{
Name = json-bro-files-analysis-2
  Product = Zeek Network Security Monitor
  DataType = "file-read"
  Conditions = [ """fuid":""", """"tx_hosts":""", """"rx_hosts":"""]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"conn_uid":"({conn_id}[^"]+)""",
    """"fuid":"({file_id}[^"]+)""",
    """"tx_hosts":"({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """"rx_hosts":"({dest_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """"source":"({log_source}[^"]+)""",
    """"total_bytes":({bytes}[^,]+)""",
    """"md5":"({md5}[^"]+)""",
    """"sha1":"({sha1}[^"]+)""",
    """"filename":"({file_name}[^"]+?(\.({file_ext}\w+))?)"""",
    """"mime_type":"({mime}[^"]+)""",
    """"source":"({protocol}[^"]+)""",
    """"analyzers":\[({analyzers}.+?)\]""",
  ]
}
json-bro-activity = {
  Vendor = Zeek
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]+@\s{0,100})?({host}\S+)""",
    """"ts\\?"{1,20}:[\[\\]*"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})"""
    #""""ts\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"]+)""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"{1,20}:({dest_port}\d{1,100})""",
    """"proto\\?"{1,20}:\\?"{1,20}({protocol}[^"]+)""",
  ]

```