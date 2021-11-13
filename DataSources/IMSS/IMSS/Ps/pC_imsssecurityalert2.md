#### Parser Content
```Java
{
Name = imss-security-alert-2
  Product = IMSS
  Conditions = [ """SPFレコードチェック""" ]

imss-email-alert = {
  Vendor = IMSS
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss zZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d{4}\/\d\d\/\d\d \d{1,100}:\d{1,100}:\d{1,100} \w+(\+|\-)\d{1,100}:\d{1,100})\s\S+\s(|({sender}[^\s]{1,2000}))\s(|"?({recipients}({recipient}[^;\s@]{1,2000}@[^;\s"]{1,2000})[^\s]{0,2000}?)"?)\s(|"?({subject}.+?)"?)\s\d\s(|({alert_name}[^\s]{1,2000}))\s\d{1,100}\s[^\s]{0,2000}?\s({bytes}\d{1,100}\.?\d{0,100})\s([^\s]{0,2000}?\s){19}(|({attachments}[^\s]{1,2000}))""",
  ]
  DupFields = [ "sender->user_email", "recipient->external_address" 
}
```