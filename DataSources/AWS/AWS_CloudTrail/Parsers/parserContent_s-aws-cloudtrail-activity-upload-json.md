#### Parser Content
```Java
{
Name = s-aws-cloudtrail-activity-upload-json
  DataType = "file-operations"
  Conditions = [  "\"AwsApiCall\"", "\"eventName\"", "\"awsRegion\"", "\"eventName\"", "\"PutObject\"" ]
  Fields = ${AWSParserTemplates.s-aws-cloudtrail-activity-json.Fields} [
    """resources":.*?"ARN":\s+"({file_name}[^"]+)""",
  ]
  DupFields = [ "activity_action->event_code" ]
}
```