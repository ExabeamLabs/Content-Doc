#### Parser Content
```Java
{
Name = json-zeek_files
  Product = Zeek Network Security Monitor
  DataType = "file-operations"
  Conditions = [ """"analyzers"""", """ zeek_files """, """"fuid"""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"conn_uids"{1,20}:\["{1,20}({conn_id}[^"]{1,2000})""",
    """"fuid"{1,20}:"{1,20}({file_id}[^"]{1,2000})""",
    """"tx_hosts"{1,20}:"{1,20}({src_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """"rx_hosts"{1,20}:"{1,20}({dest_ip}\d{1,100}.\d{1,100}.\d{1,100}.\d{1,100})""",
    """"seen_bytes"{1,20}:({bytes}[^,]{1,2000})""",
    """"md5"{1,20}:"{1,20}({md5}[^"]{1,2000})""",
    """"sha1"{1,20}:"{1,20}({sha1}[^"]{1,2000})""",
    """"mime_type"{1,20}:"{1,20}({mime}[^"]{1,2000})""",
    """"source"{1,20}:"{1,20}({protocol}[^"]{1,2000})""",
    """"analyzers"{1,20}:\[({analyzers}.+?)\]""",
  ]

json-zeek-activity = {
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Splunk
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"ts"{1,20}:({time}\d{1,100})""",
    """"uid\\?"{1,20}:\\?"{1,20}({conn_id}[^"\\]{1,2000})""",
    """"id\.orig_h\\?"{1,20}:\\?"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p\\?"{1,20}:({src_port}\d{1,100})""",
    """"id\.resp_h\\?"{1,20}:\\?"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p\\?"{1,20}:({dest_port}[a-fA-F\d.:]{1,2000})""",
  
}
```