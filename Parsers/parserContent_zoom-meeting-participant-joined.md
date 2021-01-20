#### Parser Content
```Java
{
Name = zoom-meeting-participant-joined
  Vendor = Zoom
  Product = Zoom
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|Skyformation|""", """"event":"meeting.participant""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\d+-\d+-\d+T\d+:\d+:\d+\.\d+\w ({host}[\w\-.]+) Skyformation""",
    """\WdestinationServiceName=({app}.+?)(\s+\w+=|\s*$)""",
    """"join_time"\s*:\s*({time}\d+-\d+-\d+T\d+:\d+:\d+Z)"""",
    """"event"\s*:\s*"meeting.({activity}[^"]+)"""",
    """"id"\s*:\s*"({meeting_number}\d+)"""",
    """"topic"\s*:\s*"({meeting_topic}[^"]+)"""",
    """"type"\s*:\s*({meeting_type}\d)""",
    """"host_id"\s*:\s*"({meeting_host_id}[^"]+)"""",
    """"user_name"\s*:\s*"({participant_name}[^"]+)"""",
    """"participant":\{[^\}]*"id":"({participant_id}[^"]+)"""",
    """"timezone"\s*:\s*"({meeting_timezone}[^"]+)""""
  ]
}
```