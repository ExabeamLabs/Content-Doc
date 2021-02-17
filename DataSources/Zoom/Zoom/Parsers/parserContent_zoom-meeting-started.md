#### Parser Content
```Java
{
Name = zoom-meeting-started
  Vendor = Zoom
  Product = Zoom
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|Skyformation|""", """"event":"meeting.started"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\WdestinationServiceName=({app}.+?)(\s+\w+=|\s*$)""",
    """"start_time"\s*:\s*({time}\d+-\d+-\d+T\d+:\d+:\d+Z)"""",
    """"event"\s*:\s*"meeting.({activity}started)"""",
    """"id"\s*:\s*"({meeting_number}\d+)"""",
    """"topic"\s*:\s*"({meeting_topic}[^"]+)"""",
    """"type"\s*:\s*({meeting_type}\d)""",
    """"host_id"\s*:\s*"({meeting_host_id}[^"]+)"""",
    """"timezone"\s*:\s*"({meeting_timezone}[^"]+)""""
  ]
}
```