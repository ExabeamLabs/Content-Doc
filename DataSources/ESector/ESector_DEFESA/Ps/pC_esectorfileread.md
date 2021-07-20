#### Parser Content
```Java
{
Name = esector-file-read
  DataType = "file-read"
  Conditions = [ """"pri":"user""", """"ident":"""", """"ファイル参照""", """"receivedFrom":""""]
  Fields = ${ESectorParserTemplates.esector-file-activity.Fields}[
    """ファイル参照\\",\\"({file_path}({file_parent}.*?[\\\/]{1,2000})?({file_name}[^\\\/]{1,2000}?(\.({file_ext}[^\\\.]{1,2000}))?))\\"""",
    """({event_name}ファイル参照)"""
  ]
}
```