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
      """({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s((?i)am|pm))""",
      """({event_name}An attempt was made to change an account's password)""",
      """"agent_hostname":"({host}[^"]{1,200})"""",
      """exabeam_host=(gcs-topic|({host}[\w.\-]{1,2000}))""",
      """({host}[^\s]{1,2000})\s({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s\w{2})""",
      """EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
      """timestamp"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\+\d\d\d\d)""",
      """\Wrt=({time}\d{1,100})""",
      """Security,(rn=)?({record_id}[\d]{1,2000})""",
      """({host}[\w.\-]{1,2000})\s{0,100}:\s{1,100}An attempt was made to change""",
      """\scategoryOutcome=(|/({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """({outcome}((Success|Failure|Audit)\s{1,100}\w+)|Information)(\s{1,100}|\s{0,100

}
```