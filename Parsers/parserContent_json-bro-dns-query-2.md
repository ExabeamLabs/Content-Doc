#### Parser Content
```Java
{
Name = json-bro-dns-query-2
  Product = Bro
  DataType = "dns-query"
  Conditions = [ """query":""", """"id.resp_h":""", """"id.resp_p":"""]
  Fields = ${BroParserTemplates.json-bro-activity.Fields}[
    """"host_name":"({host}[^"])""",
    """"trans_id":({query_id}[^,]+)""",
    """"query":"({query}[^"]+)""",
    """"query":"({query}[^"]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))""",
    """"qtype":({query_type}[^,]+)""",
    """"rejected":({outcome}[^\}]+)""",
    """"rcode":({response}[^,]+)""",
  ]
}
```