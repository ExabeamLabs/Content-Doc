#### Parser Content
```Java
{
Name = goanywhere-file-upload-1
  DataType = "file-upload"
  Conditions = [ """GoACHevent_type="Upload Successful"""", """GoACHcommand="Upload"""", """GoACHremote_ip="""", """GoACHuser_name="""" ]
  Fields = ${GoAnywhereParserTemplates.goanywhere-events-2.Fields}[
     """GoACHfile_path="({file_path}[^"]{0,2000}\/({file_name}[^"]{0,2000}))"""",
     """"({activity}Upload)""""
  ]
}
goanywhere-events-2 = {
    Vendor = GoAnywhere
    Product = GoAnywhere MFT
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d[+-]\d\d:\d\d)\s({dest_host}[\w\-.]{1,2000})""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """GoACHremote_ip="({src_ip}[\da-fA-F:\.]{1,100})"""",
      """GoACHlocal_ip="({dest_ip}[\da-fA-F:\.]{1,100})"""",
      """GoACHuser_name="(({user_email}[^@"]{1,2000}@[^\.]{1,2000}\.[^"]{1,2000})|(admin|666666|guest|({user}[^"]{1,2000})))"""",
      """GoACHevent_type="({event_name}[^"]{1,2000})"""",
    ]

```