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
    """"tx_hosts":"({src_ip}\d+.\d+.\d+.\d+)""",
    """"rx_hosts":"({dest_ip}\d+.\d+.\d+.\d+)""",
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
```