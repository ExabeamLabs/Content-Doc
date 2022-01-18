#### Parser Content
```Java
{
Name = wls-627
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-password-change"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """LogType="WLS"""", """EventID="627"""" ]
    Fields = [
      """({event_name}Change Password Attempt)""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """EventID="{1,20}({event_code}[^"]{1,2000})"""",
      """EventRecordID="{1,20}({record_id}[^"]{1,2000})"""",
      """CallerDomain="{1,20}({domain}[^"]{1,2000})"""",
      """CallerLogonId="{1,20}\([^,]{1,2000

}
```