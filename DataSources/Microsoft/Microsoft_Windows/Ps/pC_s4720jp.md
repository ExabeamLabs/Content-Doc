#### Parser Content
```Java
{
Name = s-4720-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-account-created"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [  "ユーザー アカウントが作成されました。" ]
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),({event_code}4720),""",
      """(?!\d{1,100})({host}[\w\-.]{1,2000}),([^,]{0,2000

}
```