#### Parser Content
```Java
{
Name = cef-checkpoint-vpn-end
  DataType = "vpn-end"
  Conditions = [ """CEF:""", """|Check Point|Mobile Access Blade|""", """|RAS Log Out|""" ]

cef-checkpoint-vpn-events = {
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = ArcSight
  TimeFormat = "epoch"
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\WAction:\s{0,100}({action}[^;]{1,2000})""",
    """\Wshost=({src_host}[\w\-.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsuser=({user}[^\s]{1,2000})""",
    """\WsourceGeoCountryCode=({src_country_code}\w+)"""
  ]
   DupFields = [ "action->event_name" 
}
```