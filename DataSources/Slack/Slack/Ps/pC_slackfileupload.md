#### Parser Content
```Java
{
Name = slack-file-upload
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """"action": "file_uploaded"""", """"date_create":""" ]
  Fields = ${SlackParserTemplates.slack-events.Fields} [
    """"file":\s{0,100}\{[^\}]{0,2000}"filetype":\s{0,100}"({file_type}[^"]{1,2000})""",
    """"file":\s{0,100}\{[^\}]{0,2000}"name":\s{0,100}"({file_name}[^"]{1,2000}?(\.({file_ext}[^"\s\.]{1,2000})?))""",
  ]
  DupFields = [ "activity->accesses" ]

slack-events = {
  Vendor = Slack
  Product = Slack
  Lms = Direct
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"date_create":\s{0,100}({time}\d{1,100})""",
    """"action":\s{0,100}"({activity}[^"]{1,2000})""",
    """"domain":\s{0,100}"({domain}[^"]{1,2000})""",
    """"user":\s{0,100}\{[^\}]{0,2000}"email":\s{0,100}"({user_email}[^"]{1,2000})""",
    """"user":\s{0,100}\{[^\}]{0,2000}"id":\s{0,100}"({user_id}[^"]{1,2000})""",
    """"user":\s{0,100}\{[^\}]{0,2000}"name":\s{0,100}"({user_fullname}[^"]{1,2000})""",
    """"context":\s{0,100}\{[^\}]{0,2000}"ip_address":\s{0,100}"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"context":\s{0,100}\{[^\}]{0,2000}"id":\s{0,100}"({dest_host}[\w\-.]{1,2000})""",
    """"file":\s{0,100}\{[^\}]{0,2000}"filetype":\s{0,100}"({file_type}[^"]{1,2000})""",
    """"file":\s{0,100}\{[^\}]{0,2000}"name":\s{0,100}"({file_name}[^"]{1,2000}?(\.({file_ext}[^"\s\.]{1,2000})?))""",
    """"ua":\s{0,100}"({user_agent}[^"]{1,2000})""",
    """"ua":\s{0,100}"[^"]{0,2000}({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """"ua":\s{0,100}"[^"]{0,2000}({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  
}
```