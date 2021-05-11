#### Parser Content
```Java
{
Name = slack-file-upload
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """"action": "file_uploaded"""", """"date_create":""" ]
  Fields = ${SlackParserTemplates.slack-events.Fields} [
    """"file":\s{0,100}\{[^\}]*"filetype":\s{0,100}"({file_type}[^"]+)""",
    """"file":\s{0,100}\{[^\}]*"name":\s{0,100}"({file_name}[^"]+?(\.({file_ext}[^"\s\.]+)?))""",
  ]
  DupFields = [ "activity->accesses" ]
}
slack-events = {
  Vendor = Slack
  Product = Slack
  Lms = Direct
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"date_create":\s{0,100}({time}\d{1,100})""",
    """"action":\s{0,100}"({activity}[^"]+)""",
    """"domain":\s{0,100}"({domain}[^"]+)""",
    """"user":\s{0,100}\{[^\}]*"email":\s{0,100}"({user_email}[^"]+)""",
    """"user":\s{0,100}\{[^\}]*"id":\s{0,100}"({user_id}[^"]+)""",
    """"user":\s{0,100}\{[^\}]*"name":\s{0,100}"({user_fullname}[^"]+)""",
    """"context":\s{0,100}\{[^\}]*"ip_address":\s{0,100}"({dest_ip}[A-Fa-f:\d.]+)""",
    """"context":\s{0,100}\{[^\}]*"id":\s{0,100}"({dest_host}[\w\-.]+)""",
    """"file":\s{0,100}\{[^\}]*"filetype":\s{0,100}"({file_type}[^"]+)""",
    """"file":\s{0,100}\{[^\}]*"name":\s{0,100}"({file_name}[^"]+?(\.({file_ext}[^"\s\.]+)?))""",
    """"ua":\s{0,100}"({user_agent}[^"]+)""",
    """"ua":\s{0,100}"[^"]*({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """"ua":\s{0,100}"[^"]*({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  ]

```