#### Parser Content
```Java
{
Name = zoom-meeting-created
  Vendor = Zoom
  Product = Zoom
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """|Skyformation|""", """"event":"meeting.created"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\d+-\d+-\d+T\d+:\d+:\d+\.\d+\w ({host}[\w\-.]+) Skyformation""",
    """\WdestinationServiceName=({app}.+?)(\s+\w+=|\s*$)""",
    """\Wend=({time}\d+)""",
    """"event"\s*:\s*"meeting.({activity}created)"""",
    """"operator"\s*:\s*"({user_email}[^\s@"]+@[^\s@"]+)"""",
    """"operator_id"\s*:\s*"({meeting_host_id}[^"]+)"""", 
    """"id"\s*:\s*({meeting_number}\d+)""",
    """"topic"\s*:\s*"({meeting_topic}[^"]+)"""",
    """"type"\s*:\s*({meeting_type}\d)""",
    """"duration"\s*:\s*({meeting_duration}\d+)""",
    """"timezone"\s*:\s*"({meeting_timezone}[^"]+)""""
  ]
}
```