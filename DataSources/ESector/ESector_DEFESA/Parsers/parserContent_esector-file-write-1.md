#### Parser Content
```Java
{
Name = esector-file-write-1
  DataType = "file-write"
  Conditions = [ """"pri":"user""", """"ident":"""", """"ファイル移動""", """"receivedFrom":""""]
  Fields = ${ESectorParserTemplates.esector-file-activity.Fields}[
    """ファイル移動\\",\\"({file_path}({file_parent}.*?[\\\/]{1,2000})?({file_name}[^\\\/]{1,2000}?(\.({file_ext}[^\\\.]{1,2000}))?))\\"""",
    """({event_name}ファイル移動)"""
  ]
}
```