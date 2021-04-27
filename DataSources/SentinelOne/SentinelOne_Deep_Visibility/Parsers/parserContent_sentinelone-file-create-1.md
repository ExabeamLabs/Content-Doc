#### Parser Content
```Java
{
Name = sentinelone-file-create-1
  DataType = "file-write"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """fileCreation {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """type"+:"+file"+,"+name"+:"+({file_path}({file_parent}[^"]+?)[\\\/]*({file_name}[^\\\/"]+?(\.({file_ext}[^\.\s"\\\/]+))?))"""",
    """({event_name}fileCreation)""",
  ]
}
```