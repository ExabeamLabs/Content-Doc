#### Parser Content
```Java
{
Name = s-4768-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-4768"
    TimeFormat = "MM/dd/yyyy hh:mm:ss a"
    Conditions = [ "4768", "Kerberos 認証チケット (TGT) が要求されました。" ]
    Fields = [ """exabeam_raw=({time}\d{1,100}/\d{1,100}/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),4768,""",
      """ComputerName =({computer_name}[\w.\-]{1,2000})""",
      """({host}(?!\d{1,100})[\w\-.]{1,2000}),([^,]{0,2000

}
```