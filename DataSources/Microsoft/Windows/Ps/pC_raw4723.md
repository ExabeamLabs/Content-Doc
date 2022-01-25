#### Parser Content
```Java
{
Name = raw-4723
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-password-change"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ "An attempt was made to change" ]
    Fields = [
      """({event_name}An attempt was made to change an account's password)""",
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
      """timestamp"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\+\d\d\d\d)""",
      """({time}(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} 20\d{2})""",
      """\Wrt=({time}\d{1,100})""",
      """Security,(rn=)?({record_id}[\d]{1,2000})""",
      """({host}[\w.\-]{1,2000})\s{0,100}:\s{1,100}An attempt was made to change""",
      """\scategoryOutcome=(|/({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """({outcome}((Success|Failure|Audit)\s{1,100}\w+)|Information)(\s{1,100}|\s{0,100

}
```