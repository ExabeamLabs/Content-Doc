#### Parser Content
```Java
{
Name = o365-sharepoint-app-activity
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ ""","SharePoint","20""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    ""","({app}SharePoint)","\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,100})?Z"(,("[^"]{0,2000}"|[^,]{0,2000})){2

}
```