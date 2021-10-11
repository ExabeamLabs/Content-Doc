#### Parser Content
```Java
{
Name = o365-onedrive-app-activity
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ ""","OneDrive","20""", ""","SharePoint",""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    ""","({app}OneDrive)","\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,100})?Z"(,("[^"]{0,2000}"|[^,]{0,2000})){2},"[^"]{0,2000}?({user_email}[^"\|]{1,2000})"(,[^,]{0,2000}){10},"({activity}[^"]{1,2000})",(("[^"]{0,2000}"|[^,]{0,2000}),){3}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)",(("[^"]{0,2000}"|[^,]{0,2000}),){7}(|"({src_ip}[a-fA-F\d.:]{1,2000})"),.*?,"SharePoint",(("[^"]{0,2000}"|[^,]{0,2000}),){10}(|"({share_path}[^"]{1,2000})"),(|"({file_name}[^"]{1,2000}?(\.({file_ext}\w+))?)"),(|"({file_parent}[^"]{1,2000})"),""",
  ]
  DupFields = [ "activity->accesses" ]
}
```