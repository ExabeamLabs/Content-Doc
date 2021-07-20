#### Parser Content
```Java
{
Name = esector-file-delete
  DataType = "file-delete"
  Conditions = [ """"pri":"user""", """"ident":"""", """"ファイル削除""", """"receivedFrom":""""]
  Fields = ${ESectorParserTemplates.esector-file-activity.Fields}[
    """ファイル削除\\",\\"({file_path}({file_parent}.*?[\\\/]{1,2000})?({file_name}[^\\\/]{1,2000}?(\.({file_ext}[^\\\.]{1,2000}))?))\\"""",
    """({event_name}ファイル削除)"""
  ]
}
```