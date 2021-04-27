#### Parser Content
```Java
{
Name = sentinelone-file-delete-1
  DataType = "file-delete"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """fileDeletion {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}fileDeletion)""",
    """type"+:"+file"+,"+name"+:"+({file_path}({file_parent}[^"]+?)[\\\/]*({file_name}[^\\\/"]+?(\.({file_ext}[^\.\s"\\\/]+))?))"""",
  ]
}
```