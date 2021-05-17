#### Parser Content
```Java
{
Name = sentinelone-web-activity-1
  DataType = "web-activity"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """http {""", """method:""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """method:\s{0,100}\\?"{1,20}({method}[^"\\]{1,2000})""",
    """url:\s{0,100}\\"{1,20}({full_url}({protocol}[^:\\\/\s,"]{1,2000}):\/*({web_domain}[^\\\/\s:,"]{1,2000})(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?"]{0,2000})?(\?({uri_query}[^"\s]{0,2000}))?)\\"""",
    """https:.+?({top_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
  ]
}
```