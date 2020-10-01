#### Parser Content
```Java
{
Name = slack-file-upload
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """"action": "file_uploaded"""", """"date_create":""" ]
  Fields = ${SlackParserTemplates.slack-events.Fields} [
    """"file":\s*\{[^\}]*"filetype":\s*"({file_type}[^"]+)""",
    """"file":\s*\{[^\}]*"name":\s*"({file_name}[^"]+?(\.({file_ext}[^"\s\.]+)?))""",
  ]
  DupFields = [ "activity->accesses" ]
}
```