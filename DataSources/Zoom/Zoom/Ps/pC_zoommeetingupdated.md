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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\WdestinationServiceName =({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"operator"\s{0,100}:\s{0,100}"({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000})"""",
    """"operator_id"\s{0,100}:\s{0,100}"({meeting_host_id}[^"]{1,2000})"""",
    """"event"\s{0,100}:\s{0,100}"meeting.({activity}updated)"""",
    """"old_object"\s{0,100}:\s{0,100}\{.*?"password"\s{0,100}:\s{0,100}"({old_password}[^"]{1,2000})"""",
    """"object"\s{0,100}:\s{0,100}\{.*?"password"\s{0,100}:\s{0,100}"({new_password}[^"]{1,2000})"""",
    """"object"\s{0,100}:\s{0,100}\{"id"\s{0,100}:\s{0,100}({meeting_number}\d{1,100})""",
    """"time_stamp"\s{0,100}:\s{0,100}"({time}\d{1,100})"""
  ]


}
```