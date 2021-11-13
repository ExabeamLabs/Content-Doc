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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\WdestinationServiceName =({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"join_time"\s{0,100}:\s{0,100}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)"""",
    """"event"\s{0,100}:\s{0,100}"meeting.({activity}[^"]{1,2000})"""",
    """"id"\s{0,100}:\s{0,100}"({meeting_number}\d{1,100})"""",
    """"topic"\s{0,100}:\s{0,100}"({meeting_topic}[^"]{1,2000})"""",
    """"type"\s{0,100}:\s{0,100}({meeting_type}\d)""",
    """"host_id"\s{0,100}:\s{0,100}"({meeting_host_id}[^"]{1,2000})"""",
    """"user_name"\s{0,100}:\s{0,100}"({participant_name}[^"]{1,2000})"""",
    """"participant":\{[^\}]{0,2000}"id":"({participant_id}[^"]{1,2000})"""",
    """"timezone"\s{0,100}:\s{0,100}"({meeting_timezone}[^"]{1,2000})""""
  ]


}
```