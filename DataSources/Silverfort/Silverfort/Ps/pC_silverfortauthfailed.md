#### Parser Content
```Java
{
Name = silverfort-auth-failed
  DataType = "authentication-failed"
  Conditions = [ """ CEF:""", """|Silverfort|Admin Console|""", """|MFA|MFA request|""", """SilverfortMfaResponse""", """ cs2=Denied""" ]
  Fields = ${SilverfortParserTemplates.silverfort-authentication-attempt.Fields}[
	"""\scs5=({failure_reason}[^=]{1,2000}?)\s{1,100}\w+="""
  ]
}
silverfort-authentication-attempt = {
    Vendor = Silverfort
    Product = Silverfort
    Lms = Direct
    TimeFormat ="MM/dd/yyyy HH:mm:ss.SSS"
    Fields = [
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """\|rt=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
      """dntdom=(n\/a|({domain}[^=]{1,2000}?))\s{1,100}\w+=""",
      """suser=((({domain}[^\\\s]{1,2000}?)\\({user}[^=]{1,2000}?)\s{1,100}\w+=)|({user_email}[^@]{1,2000}@[^=]{1,2000}?)\s{1,100}\w+=)""",
      """src=(null|({src_ip}[a-fA-F\d:.]{1,2000}))\s{1,100}\w+=""",
      """shost=(n\/a|({src_host}[^=]{1,2000}?))\s{1,100}\w+=""",
      """dhost=(({dest_ip}[a-fA-F\d:.]{1,2000})|({dest_host}[^=]{1,2000}?))\s{1,100}\w+=""",
      """\scs2=({action}[^=]{1,2000}?)\s{1,100}\w+=""",
      """\sapp=({auth_method}[^=]{1,2000}?)\s{1,100}\w+="""
    ]

```