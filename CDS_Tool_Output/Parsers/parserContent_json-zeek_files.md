#### Parser Content
```Java
{
Name = json-zeek_files
  DataType = "file-operations"
  Conditions = [ """"analyzers"""", """ zeek_files """, """"fuid"""" ]
  Fields = ${BroParserTemplates.json-zeek-activity.Fields}[
    """"conn_uids"+:\["+({conn_id}[^"]+)""",
    """"fuid"+:"+({file_id}[^"]+)""",
    """"tx_hosts"+:"+({src_ip}\d+.\d+.\d+.\d+)""",
    """"rx_hosts"+:"+({dest_ip}\d+.\d+.\d+.\d+)""",
    """"seen_bytes"+:({bytes}[^,]+)""",
    """"md5"+:"+({md5}[^"]+)""",
    """"sha1"+:"+({sha1}[^"]+)""",
    """"mime_type"+:"+({mime}[^"]+)""",
    """"source"+:"+({protocol}[^"]+)""",
    """"analyzers"+:\[({analyzers}.+?)\]""",
  ]
}
```