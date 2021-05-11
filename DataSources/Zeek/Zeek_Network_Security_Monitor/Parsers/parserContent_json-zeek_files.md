#### Parser Content
```Java
{
Name = json-zeek_files
  Product = Zeek Network Security Monitor
  DataType = "file-operations"
  Conditions = [ """"analyzers"""", """ zeek_files """, """"fuid"""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"conn_uids"{1,20}:\["{1,20}({conn_id}[^"]+)""",
    """"fuid"{1,20}:"{1,20}({file_id}[^"]+)""",
    """"tx_hosts"{1,20}:"{1,20}({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """"rx_hosts"{1,20}:"{1,20}({dest_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """"seen_bytes"{1,20}:({bytes}[^,]+)""",
    """"md5"{1,20}:"{1,20}({md5}[^"]+)""",
    """"sha1"{1,20}:"{1,20}({sha1}[^"]+)""",
    """"mime_type"{1,20}:"{1,20}({mime}[^"]+)""",
    """"source"{1,20}:"{1,20}({protocol}[^"]+)""",
    """"analyzers"{1,20}:\[({analyzers}.+?)\]""",
  ]
}
json-zeek-activity = {
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Splunk
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^@=]+@\s{0,100})?({host}\S+)""",
    """"ts"{1,20}:({time}\d{1,100})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"\\]+)""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]+)""",
  ]

```