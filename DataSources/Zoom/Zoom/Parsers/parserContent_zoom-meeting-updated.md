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
    """\WdestinationServiceName=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"operator"\s{0,100}:\s{0,100}"({user_email}[^\s@"]+@[^\s@"]+)"""",
    """"operator_id"\s{0,100}:\s{0,100}"({meeting_host_id}[^"]+)"""",
    """"event"\s{0,100}:\s{0,100}"meeting.({activity}updated)"""",
    """"old_object"\s{0,100}:\s{0,100}\{.*?"password"\s{0,100}:\s{0,100}"({old_password}[^"]+)"""",
    """"object"\s{0,100}:\s{0,100}\{.*?"password"\s{0,100}:\s{0,100}"({new_password}[^"]+)"""",
    """"object"\s{0,100}:\s{0,100}\{"id"\s{0,100}:\s{0,100}({meeting_number}\d{1,100})""",
    """"time_stamp"\s{0,100}:\s{0,100}"({time}\d{1,100})"""
  ]
}
```