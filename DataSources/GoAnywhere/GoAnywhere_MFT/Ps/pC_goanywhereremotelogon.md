#### Parser Content
```Java
{
Name = goanywhere-remote-logon
  DataType = "remote-logon"
  Conditions = [ """GoAnywhereServicesevent_type="Login Successful"""","""GoAnywhereServicescommand="Login"""","""GoAnywhereServicesremote_ip="""" ]

goanywhere-events = {
    Vendor = GoAnywhere
    Product = GoAnywhere MFT
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d[+-]\d\d:\d\d)\s({dest_host}[\w\-.]{1,2000})""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """GoAnywhereServiceslocal_ip="({dest_ip}[A-Fa-f\d.:]{1,2000})"""",
      """GoAnywhereServicesremote_ip="({src_ip}[A-Fa-f\d.:]{1,2000})"""",
      """GoAnywhereServicesuser_name="(({user_email}[^@"]{1,2000}@[^\.]{1,2000}\.[^"]{1,2000})|(admin|666666|guest|({user}[^"]{1,2000})))"""",
      """GoAnywhereServicesevent_type="({event_name}[^"]{1,2000})"""",
    
}
```