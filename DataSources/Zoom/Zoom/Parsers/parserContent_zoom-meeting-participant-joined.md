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
    """\WdestinationServiceName=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"join_time"\s{0,100}:\s{0,100}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)"""",
    """"event"\s{0,100}:\s{0,100}"meeting.({activity}[^"]+)"""",
    """"id"\s{0,100}:\s{0,100}"({meeting_number}\d{1,100})"""",
    """"topic"\s{0,100}:\s{0,100}"({meeting_topic}[^"]+)"""",
    """"type"\s{0,100}:\s{0,100}({meeting_type}\d)""",
    """"host_id"\s{0,100}:\s{0,100}"({meeting_host_id}[^"]+)"""",
    """"user_name"\s{0,100}:\s{0,100}"({participant_name}[^"]+)"""",
    """"participant":\{[^\}]*"id":"({participant_id}[^"]+)"""",
    """"timezone"\s{0,100}:\s{0,100}"({meeting_timezone}[^"]+)""""
  ]
}
```