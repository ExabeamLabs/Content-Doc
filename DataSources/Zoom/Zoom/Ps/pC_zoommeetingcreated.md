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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\WdestinationServiceName =({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wend=({time}\d{1,100})""",
    """"event"\s{0,100}:\s{0,100}"meeting.({activity}created)"""",
    """"operator"\s{0,100}:\s{0,100}"({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000})"""",
    """"operator_id"\s{0,100}:\s{0,100}"({meeting_host_id}[^"]{1,2000})"""", 
    """"id"\s{0,100}:\s{0,100}({meeting_number}\d{1,100})""",
    """"topic"\s{0,100}:\s{0,100}"({meeting_topic}[^"]{1,2000})"""",
    """"type"\s{0,100}:\s{0,100}({meeting_type}\d)""",
    """"duration"\s{0,100}:\s{0,100}({meeting_duration}\d{1,100})""",
    """"timezone"\s{0,100}:\s{0,100}"({meeting_timezone}[^"]{1,2000})""""
  ]


}
```