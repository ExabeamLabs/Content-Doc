#### Parser Content
```Java
{
Name = json-bro-files-analysis-2
  DataType = "file-read"
  Conditions = [ """fuid":""", """"tx_hosts":""", """"rx_hosts":"""]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"conn_uid":"({conn_id}[^"]+)""",
    """"fuid":"({file_id}[^"]+)""",
    """"tx_hosts":"({src_ip}\d+.\d+.\d+.\d+)""",
    """"rx_hosts":"({dest_ip}\d+.\d+.\d+.\d+)""",
    """"source":"({source}[^"]+)""",
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
  Vendor = Bro
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
    """"ts\\?"+:[\[\\]*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})"""
    #""""ts\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3})""",
    """"uid\\?"+:\\?"+({conn_id}[^"]+)""",
    """"id\.orig_h\\?"+:\\?"+({src_ip}[a-fA-F\d.:]+)""",
    """"id\.orig_p\\?"+:({src_port}\d+)""",
    """"id\.resp_h\\?"+:\\?"+({dest_ip}[a-fA-F\d.:]+)""",
    """"id\.resp_p\\?"+:({dest_port}\d+)""",
    """"proto\\?"+:\\?"+({protocol}[^"]+)""",
  ]

```