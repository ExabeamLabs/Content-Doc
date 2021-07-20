#### Parser Content
```Java
{
Name = esector-file-write
  DataType = "file-write"
  Conditions = [ """"pri":"user""", """"ident":"""", """"ファイル書込""", """"receivedFrom":""""]
  Fields = ${ESectorParserTemplates.esector-file-activity.Fields}[
    """ファイル書込\\",\\"({file_path}({file_parent}.*?[\\\/]{1,2000})?({file_name}[^\\\/]{1,2000}?(\.({file_ext}[^\\\.]{1,2000}))?))\\"""",
    """({event_name}ファイル書込)"""
  ]
}
```