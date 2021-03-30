#### Parser Content
```Java
{
Name = slack-file-download
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """"action": "file_downloaded"""", """"date_create":""" ]
  Fields = ${SlackParserTemplates.slack-events.Fields} [
    """"file":\s*\{[^\}]*"filetype":\s*"({file_type}[^"]+)""",
    """"file":\s*\{[^\}]*"name":\s*"({file_name}[^"]+?(\.({file_ext}[^"\s\.]+)?))""",
  ]
  DupFields = [ "activity->accesses" ]
}
slack-events = {
  Vendor = Slack
  Product = Slack
  Lms = Direct
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"date_create":\s*({time}\d+)""",
    """"action":\s*"({activity}[^"]+)""",
    """"domain":\s*"({domain}[^"]+)""",
    """"user":\s*\{[^\}]*"email":\s*"({user_email}[^"]+)""",
    """"user":\s*\{[^\}]*"id":\s*"({user_id}[^"]+)""",
    """"user":\s*\{[^\}]*"name":\s*"({user_fullname}[^"]+)""",
    """"context":\s*\{[^\}]*"ip_address":\s*"({dest_ip}[A-Fa-f:\d.]+)""",
    """"context":\s*\{[^\}]*"id":\s*"({dest_host}[\w\-.]+)""",
    """"file":\s*\{[^\}]*"filetype":\s*"({file_type}[^"]+)""",
    """"file":\s*\{[^\}]*"name":\s*"({file_name}[^"]+?(\.({file_ext}[^"\s\.]+)?))""",
    """"ua":\s*"({user_agent}[^"]+)""",
    """"ua":\s*"[^"]*({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """"ua":\s*"[^"]*({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  ]

```