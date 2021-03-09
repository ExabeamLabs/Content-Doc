#### Parser Content
```Java
{
Name = zoom-meeting-ended
  Vendor = Zoom
  Product = Zoom
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|Skyformation|""", """"event":"meeting.ended"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\WdestinationServiceName=({app}.+?)(\s+\w+=|\s*$)""",
    """"end_time"\s*:\s*({time}\d+-\d+-\d+T\d+:\d+:\d+Z)"""",
    """"event"\s*:\s*"meeting.({activity}ended)"""",
    """"id"\s*:\s*"({meeting_number}\d+)""",
    """"topic"\s*:\s*"({meeting_topic}[^"]+)"""",
    """"type"\s*:\s*({meeting_type}\d)""",
    """"duration"\s*:\s*({meeting_duration}\d+)""",
    """"timezone"\s*:\s*"({meeting_timezone}[^"]+)"""",
    """"host_id"\s*:\s*"({meeting_host_id}[^"]+)""""
  ]
}
```