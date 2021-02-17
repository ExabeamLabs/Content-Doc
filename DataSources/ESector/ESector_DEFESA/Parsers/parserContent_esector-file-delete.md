#### Parser Content
```Java
{
Name = esector-file-delete
  DataType = "file-delete"
  Conditions = [ """"pri":"user""", """"ident":"""", """"ファイル削除""", """"receivedFrom":""""]
  Fields = ${ESectorParserTemplates.esector-file-activity.Fields}[
    """ファイル削除\\",\\"({file_path}({file_parent}.*?[\\\/]+)?({file_name}[^\\\/]+?(\.({file_ext}[^\\\.]+))?))\\"""",
    """({event_name}ファイル削除)"""
  ]
}
```