#### Parser Content
```Java
{
Name = esector-file-write-2
  DataType = "file-write"
  Conditions = [ """"pri":"user""", """"ident":"""", """"ファイルコピー""", """"receivedFrom":""""]
  Fields = ${ESectorParserTemplates.esector-file-activity.Fields}[
    """ファイルコピー\\",\\"({file_path}({file_parent}.*?[\\\/]+)?({file_name}[^\\\/]+?(\.({file_ext}[^\\\.]+))?))\\"""",
    """({event_name}ファイルコピー)"""
  ]
}
```