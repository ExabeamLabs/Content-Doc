#### Parser Content
```Java
{
Name = sentinelone-web-activity-2
  DataType = "web-activity"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """url:""" , "http {"]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """,({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)""",
    """url:\s{0,100}"{1,20}({full_url}({protocol}[^:\\\/\s,"]+):\/*({web_domain}[^\\\/\s:,"]+)(:({dest_port}\d{1,100}))({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?)""",
    """\shttp.+?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)"""
  ]
}
```