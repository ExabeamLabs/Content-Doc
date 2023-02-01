#### Parser Content
```Java
{
Name = cef-symantec-dlp-alert-2
    Vendor = Symantec
    Product = Symantec DLP
    Lms = ArcSight
    DataType = "dlp-alert"
    TimeFormat = "MMMM dd, yyyy HH:mm:ss"
    Conditions = [ """CEF""","""|Symantec|DLP|""","""Application_Name =""","""Sender=""" ]
    Fields = [
      """({host}[\w\-.]{1,2000})\s{1,100}CEF:""",
      """Occurred_On="({time}\w+\s\d{1,2

}
```