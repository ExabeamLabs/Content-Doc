#### Parser Content
```Java
{
Name = esector-file-write-2
  DataType = "file-write"
  Conditions = [ """"pri":"user""", """"ident":"""", """"ファイルコピー""", """"receivedFrom":""""]
  Fields = ${ESectorParserTemplates.esector-file-activity.Fields}[
    """ファイルコピー\\",\\"({file_path}({file_parent}.*?[\\\/]{1,2000})?({file_name}[^\\\/]{1,2000}?(\.({file_ext}[^\\\.]{1,2000}))?))\\"""",
    """({event_name}ファイルコピー)"""
  ]
}
```