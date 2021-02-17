#### Parser Content
```Java
{
Name = sentinelone-file-modify-1
  DataType = "file-write"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """fileModification {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}fileModification)""",
    """type"+:"+file"+,"+name"+:"+({file_path}({file_parent}[^"]+?)[\\\/]*({file_name}[^\\\/"]+?(\.({file_ext}[^\.\s"\\\/]+))?))"""",
  ]
}
```