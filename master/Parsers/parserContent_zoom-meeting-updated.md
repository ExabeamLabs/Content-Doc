#### Parser Content
```Java
{
Name = zoom-meeting-updated
  Vendor = Zoom
  Product = Zoom
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """|Skyformation|""", """"event":"meeting.updated"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\d+-\d+-\d+T\d+:\d+:\d+\.\d+\w ({host}[\w\-.]+) Skyformation""",
    """\WdestinationServiceName=({app}.+?)(\s+\w+=|\s*$)""",
    """"operator"\s*:\s*"({user_email}[^\s@"]+@[^\s@"]+)"""",
    """"operator_id"\s*:\s*"({meeting_host_id}[^"]+)"""",
    """"event"\s*:\s*"meeting.({activity}updated)"""",
    """"old_object"\s*:\s*\{.*?"password"\s*:\s*"({old_password}[^"]+)"""",
    """"object"\s*:\s*\{.*?"password"\s*:\s*"({new_password}[^"]+)"""",
    """"object"\s*:\s*\{"id"\s*:\s*({meeting_number}\d+)""",
    """"time_stamp"\s*:\s*"({time}\d+)"""
  ]
}
```