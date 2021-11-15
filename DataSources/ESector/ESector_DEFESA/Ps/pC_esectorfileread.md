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

esector-file-activity {
    Vendor = ESector
    Product = ESector DEFESA
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)[+-]\d\d:\d\d\s{1,100}\w+""",
      """receivedFrom":"({host}[^"]{1,2000})""",
      """host":"({host_ip}[a-fA-F:\.\d]{1,2000})"""",
      """ident":"({app}[^"]{1,2000})"""",
      """"message":([^,]{1,2000},){2}\\"({src_host}[^\\"]{1,2000})\\"""",
      """"message":([^,]{1,2000},){3}\\"([\w+\\-]{1,2000}?-)?({user}[^\\"]{1,2000})\\""""
    
}
```