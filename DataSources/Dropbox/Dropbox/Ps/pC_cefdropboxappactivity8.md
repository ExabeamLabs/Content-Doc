#### Parser Content
```Java
{
Name = cef-dropbox-app-activity-8
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"reports"}""" ]

cef-dropbox-activity = {
  Vendor = Dropbox
  Product = Dropbox
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) \d{1,100} \d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ""",
    """"timestamp":"({time}[^"]{1,2000})""",
    """"host_name":"({host}[^"]{1,2000})""",
    """"actor":[^\}]{0,2000}?"display_name":\s{0,100}"(?:N\/A|({user_fullname}[^"@]{1,2000}))"""",
    """"actor":[^\}]{0,2000}?"email":\s{0,100}"(?:N\/A|({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000}))"""",
    """"event_type":(\{"\.tag":)?\s{0,100}"({activity}[^"]{1,2000})"""",
    """"description":\s{0,100}"({additional_info}[^"]{1,2000})"""",
    """"ip_address":\s{0,100}"({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}))""",
    """({app}Dropbox)""",
  
}
```