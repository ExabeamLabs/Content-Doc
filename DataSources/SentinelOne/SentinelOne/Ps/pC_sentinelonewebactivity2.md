#### Parser Content
```Java
{
Name = sentinelone-web-activity-2
  DataType = "web-activity"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """url:""" , "http {"]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """,({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)""",
    """url:\s{0,100}"{1,20}({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):\/{0,20})?({web_domain}[^\\\/\s:,"\?]{1,2000})(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?)"""",
  ]
}
```